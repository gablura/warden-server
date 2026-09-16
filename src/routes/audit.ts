import type { FastifyInstance } from "fastify";
import { prisma, serializeBigInts } from "../db/client.js";
import { resolveDeployment } from "../chain/orgContracts.js";
import { optionalAuth } from "../auth/clerkAuth.js";
import { cursorQuerySchema, cursorPaginatedQuery, cursorWhere, encodeCursor } from "../db/pagination.js";

// Events carry no org column — the agent address is the join key to the
// agents table, whose org stamp is kept truthful by the indexers (see
// watchPolicyEvents / watchPaymentEvents). Scoping therefore resolves the
// caller's deployment once and filters events by the agents of that same
// deployment — the exact scope rule /agents and /approvals use.
async function scopedAuditWhere(orgId: string | null | undefined) {
  const deployment = await resolveDeployment(orgId ?? null);
  const agents = await prisma.agent.findMany({
    where: deployment.orgId === null ? { organizationId: null } : { organizationId: deployment.orgId },
    select: { address: true },
  });
  return { agent: { in: agents.map((a) => a.address) } };
}

export async function auditRoutes(app: FastifyInstance) {
  app.get<{
    Querystring: { agent?: string; from?: string; to?: string; limit?: string; cursor?: string };
  }>("/audit", { preHandler: optionalAuth() }, async (req) => {
    const { agent, from, to, limit: rawLimit, cursor: rawCursor } = req.query;

    // An explicit ?agent= narrows within the caller's scope — if the agent
    // lives on another deployment the result is simply empty, never another
    // org's events. Lowercased like agents.ts: event rows store the
    // indexer's lowercase form, so a checksummed query must not miss.
    const scope = await scopedAuditWhere(req.operator?.orgId);
    const whereAgent = agent ? { AND: [scope, { agent: agent.toLowerCase() }] } : scope;

    const result = await cursorPaginatedQuery(
      (take, cursor) =>
        prisma.event.findMany({
          where: {
            ...whereAgent,
            timestamp: {
              gte: from ? new Date(from) : undefined,
              lte: to ? new Date(to) : undefined,
            },
            ...(cursor ? cursorWhere(cursor, "desc") : {}),
          },
          orderBy: [{ timestamp: "desc" }, { id: "desc" }],
          take,
        }),
      { limit: rawLimit, cursor: rawCursor },
    );

    const last = result.data[result.data.length - 1];
    return serializeBigInts({
      ...result,
      nextCursor: result.hasMore && last ? encodeCursor(last.id, last.timestamp) : null,
    });
  });

  app.get("/audit/export", { preHandler: optionalAuth() }, async (req, reply) => {
    const rows = await prisma.event.findMany({ where: await scopedAuditWhere(req.operator?.orgId), orderBy: { timestamp: "desc" } });
    const header = "timestamp,agent,counterparty,amount,decision\n";
    const csv = rows
      .map((r) => `${r.timestamp.toISOString()},${r.agent},${r.counterparty},${r.amount.toString()},${r.decision}`)
      .join("\n");
    reply.header("Content-Type", "text/csv").send(header + csv);
  });
}
