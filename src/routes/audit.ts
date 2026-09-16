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
    // Streams the caller's scoped audit trail as CSV, page by page.
    //
    // This used to be one unbounded findMany over an append-only table with
    // the whole CSV assembled in memory — the exact "cheap full-table scan
    // and a huge payload" problem the hardening review (§4) warns about,
    // here multiplied by an export intent. Streaming keeps memory flat no
    // matter how large the export grows: each page is written to the socket
    // (respecting backpressure) and released before the next is fetched.
    const scope = await scopedAuditWhere(req.operator?.orgId);

    // The first page is fetched BEFORE the response starts, so a failing
    // database surfaces as a normal 500 instead of a truncated 200 CSV.
    const firstRows = await prisma.event.findMany({
      where: scope,
      orderBy: [{ timestamp: "desc" }, { id: "desc" }],
      take: EXPORT_PAGE_SIZE,
    });

    reply.hijack();
    const res = reply.raw;
    res.writeHead(200, {
      "content-type": "text/csv; charset=utf-8",
      "content-disposition": 'attachment; filename="audit-export.csv"',
    });

    let streamError: unknown;
    res.on("error", (err) => {
      streamError = err;
    });

    const write = async (chunk: string): Promise<void> => {
      if (streamError) throw streamError;
      if (res.write(chunk)) return;
      // Backpressure: the client is slower than the DB — wait for the
      // socket to drain instead of buffering the whole export.
      await new Promise<void>((resolve) => res.once("drain", resolve));
    };

    try {
      await write("timestamp,agent,counterparty,amount,decision\n");
      let rows = firstRows;
      for (;;) {
        for (const r of rows) {
          await write(
            `${csvField(r.timestamp.toISOString())},${csvField(r.agent)},${csvField(r.counterparty)},${r.amount.toString()},${csvField(r.decision)}\n`,
          );
        }
        if (rows.length < EXPORT_PAGE_SIZE) break;
        // Keyset advance: anchored to the last row's id, one row past it —
        // stable under concurrent writes, exactly like /audit's cursor.
        const last = rows[rows.length - 1]!;
        rows = await prisma.event.findMany({
          where: scope,
          orderBy: [{ timestamp: "desc" }, { id: "desc" }],
          take: EXPORT_PAGE_SIZE,
          cursor: { id: last.id },
          skip: 1,
        });
        if (rows.length === 0) break;
      }
    } catch (err) {
      // Mid-stream there is no status line left to change — end the
      // response and log loudly so the truncation is traceable.
      req.log.error({ err }, "audit export stream failed mid-response — the CSV is truncated");
    } finally {
      res.end();
    }
  });
}

/// Rows per streaming page of the CSV export. Large enough that page-fetch
/// overhead is negligible; small enough that a page fits comfortably in
/// memory.
const EXPORT_PAGE_SIZE = 1_000;

/// Minimal RFC-4180 field escaping. The decision field embeds the on-chain
/// rejection reason ("blocked: <reason>"), which can contain commas,
/// quotes, and newlines — without escaping those silently corrupt the CSV
/// column layout.
function csvField(value: string): string {
  return /[",\n\r]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}
