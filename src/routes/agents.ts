import type { FastifyInstance } from "fastify";
import type { Agent } from "@prisma/client";
import { prisma, serializeBigInts } from "../db/client.js";
import { readAgentPolicies, readAgentPolicy, type AgentPolicySnapshot } from "../chain/policyState.js";
import { limitQuerySchema, paginatedQuery, cursorQuerySchema, cursorPaginatedQuery, cursorWhere, encodeCursor } from "../db/pagination.js";

// EVM addresses are case-insensitive; checksum casing is a display convention.
// The indexer stores the lowercase form it gets from the event args, so
// normalizing here keeps a checksummed URL from missing its own agent row.
const normalizeAddress = (address: string) => address.toLowerCase();

/// Caps and spend come from PolicyRegistry, not the indexed row.
///
/// `agents.spent_today` is incremented by the event indexer and never rolled
/// over at the UTC day boundary, so the stored column is wrong from midnight
/// until that agent's next payment of the day — exactly the window an operator
/// is most likely to be looking at it. The live read is the source of truth,
/// so these fields are overwritten rather than merged, and `policySource` makes
/// that explicit for clients. Label, status, and timestamps are pure dashboard
/// metadata and stay DB-sourced.
function withLivePolicy(agent: Agent, policy: AgentPolicySnapshot) {
  return {
    ...agent,
    dailyCap: policy.dailyCap,
    perTxCap: policy.perTxCap,
    escalationThreshold: policy.escalationThreshold,
    spentToday: policy.spentToday,
    remainingToday: policy.remainingToday,
    lastResetDay: policy.lastResetDay,
    currentDay: policy.currentDay,
    // False means the registry has never seen this address, so the row is
    // historical and every policy value above is zero by definition.
    policyExists: policy.exists,
    policySource: "chain" as const,
    blockNumber: policy.blockNumber,
  };
}

export async function agentRoutes(app: FastifyInstance) {
  app.get<{ Querystring: { limit?: string } }>("/agents", async (req) => {
    const { limit } = limitQuerySchema.parse(req.query);

    const result = await paginatedQuery(
      (take) => prisma.agent.findMany({ take }),
      limit,
    );

    const policies = await readAgentPolicies(result.data.map((agent) => normalizeAddress(agent.address)));

    const enriched = result.data.map((agent, index) => withLivePolicy(agent, policies[index]!));

    // Sorted on live spend — the old `orderBy: { spentToday: "desc" }` sorted on
    // a column this route no longer trusts.
    enriched.sort((a, b) => (b.spentToday > a.spentToday ? 1 : b.spentToday < a.spentToday ? -1 : 0));

    return serializeBigInts({ data: enriched, hasMore: result.hasMore });
  });

  app.get<{ Params: { address: string }; Querystring: { limit?: string; cursor?: string } }>("/agents/:address", async (req, reply) => {
    const address = normalizeAddress(req.params.address);

    const agent = await prisma.agent.findUnique({ where: { address } });
    if (!agent) return reply.code(404).send({ error: "agent not found" });

    // Fail-closed: if the chain read rejects, the whole request 503s (see the
    // error handler in server.ts) rather than answering with indexed values.
    const [policy, recentPayments] = await Promise.all([
      readAgentPolicy(address),
      cursorPaginatedQuery(
        (take, cursor) =>
          prisma.event.findMany({
            where: { agent: address, ...(cursor ? cursorWhere(cursor, "desc") : {}) },
            orderBy: [{ timestamp: "desc" }, { id: "desc" }],
            take,
          }),
        req.query,
      ),
    ]);

    const last = recentPayments.data[recentPayments.data.length - 1];
    return serializeBigInts({
      agent: withLivePolicy(agent, policy),
      recentPayments: {
        ...recentPayments,
        nextCursor: recentPayments.hasMore && last ? encodeCursor(last.id, last.timestamp) : null,
      },
    });
  });
}