import type { FastifyInstance } from "fastify";
import { prisma, serializeBigInts } from "../db/client.js";
import { spendGuard } from "../chain/client.js";
import { serializeTx } from "../chain/txQueue.js";
import { readAgentPolicies } from "../chain/policyState.js";
import { broadcast } from "../ws/broadcast.js";
import { requireRole } from "../auth/apiKeyAuth.js";
import { limitQuerySchema, paginatedQuery } from "../db/pagination.js";

// Same shape as policies.ts's gas-spending routes — approver key required,
// tight rate limit, since these send real transactions.
const gasSpendingRoute = {
  preHandler: requireRole("approver"),
  config: { rateLimit: { max: 20, timeWindow: "1 minute" } },
};

/// Throws when the request is already resolved on-chain, so the caller can
/// answer with a cheap 409 instead of paying gas for a revert.
///
/// This closes both race windows the review identified in one check:
/// two approvers clicking within the same few seconds, and the indexer-lag
/// window where Postgres still shows a request as pending after the chain
/// has resolved it. The read happens on-chain, at submission time, inside
/// the same serialized queue as the write — so within this process, no
/// second approval can slip in between the check and the send. The chain
/// itself remains the final arbiter (require(!r.resolved) reverts anything
/// this check somehow misses).
class AlreadyResolvedError extends Error {
  constructor() {
    super("request already resolved on-chain");
  }
}

/// Per-credential approval scoping (see credentials.ts). An approver
/// credential may declare a maxApproval ceiling (in base units); requests
/// above it are refused before any transaction is signed. The amount comes
/// from the indexed PendingRequest row; if the row hasn't been indexed yet
/// the scope check passes, because failing closed here would let an indexer
/// lag make *all* approvals impossible, and the ceiling is a scoping
/// refinement, not the daily-cap enforcement (which lives on-chain).
async function withinApprovalScope(requestId: bigint, operatorMaxApproval: bigint | undefined) {
  if (operatorMaxApproval === undefined) return;
  const pending = await prisma.pendingRequest.findUnique({ where: { requestId } });
  if (!pending) return; // see comment above
  if (pending.amount > operatorMaxApproval) {
    throw new Error(`approval amount exceeds this credential's maxApproval ceiling`);
  }
}

async function ensureUnresolved(requestId: bigint) {
  const pending = await spendGuard.read.read.pending([requestId]);
  // pending() returns (agent, counterparty, amount, resolved) in declaration order.
  if (pending[3]) throw new AlreadyResolvedError();
}

export async function approvalRoutes(app: FastifyInstance) {
  app.get<{ Querystring: { limit?: string } }>("/approvals", async (req) => {
    const { limit } = limitQuerySchema.parse(req.query);

    const result = await paginatedQuery(
      (take) =>
        prisma.pendingRequest.findMany({
          where: { resolved: false },
          orderBy: { createdAt: "asc" },
          take,
        }),
      limit,
    );

    // Make the daily-cap collision visible before anyone clicks approve.
    // On-chain, an escalated request only touches spentToday at approval
    // time — so two pending escalations can each "fit" alone but not
    // together, and the loser currently finds out as a reverted, gas-
    // costing transaction. Here, queued requests reserve headroom in
    // createdAt order: a request fits if spentToday plus its own amount
    // plus everything queued ahead of it stays under the live daily cap.
    // Live caps/spend come from the same multicall path /agents uses.
    const agents = [...new Set(result.data.map((r) => r.agent))];
    const policies = await readAgentPolicies(agents);
    const policyByAgent = new Map(agents.map((agent, i) => [agent, policies[i]!]));

    const reserved = new Map<string, bigint>(); // agent -> amount queued ahead
    const enriched = result.data.map((request) => {
      const policy = policyByAgent.get(request.agent)!;
      const ahead = reserved.get(request.agent) ?? 0n;
      reserved.set(request.agent, ahead + request.amount);
      const spentAfterAhead = policy.spentToday + ahead;
      return {
        ...request,
        remainingToday: policy.remainingToday,
        policyExists: policy.exists,
        reservedAhead: ahead,
        // False can mean "doesn't fit" *or* "policy unreadable" — the
        // exists/policySource flags distinguish the two for clients.
        wouldFitNow: policy.exists && spentAfterAhead + request.amount <= policy.dailyCap,
      };
    });

    return serializeBigInts({ data: enriched, hasMore: result.hasMore });
  });

  app.post<{ Params: { id: string } }>("/approvals/:id/approve", gasSpendingRoute, async (req, reply) => {
    // The preHandler guarantees req.operator is set; this guard keeps the
    // handler honest if the middleware wiring ever changes.
    if (!req.operator) return reply.code(500).send({ error: "internal_error", message: "operator identity missing" });

    const requestId = BigInt(req.params.id);
    await withinApprovalScope(requestId, req.operator.maxApproval);

    try {
      // Pre-check and submission share the approver wallet's tx queue, so
      // no second request from this process can interleave between them.
      const hash = await serializeTx("approver", async () => {
        await ensureUnresolved(requestId);
        return spendGuard.approver.write.approvePending([requestId]);
      });
      await recordOperatorAction(req.operator, "approve", req.params.id, hash);
      broadcast({ type: "approval_resolved", requestId: req.params.id, decision: "approved", txHash: hash, by: req.operator.id });
      return reply.send({ txHash: hash });
    } catch (err) {
      if (err instanceof AlreadyResolvedError) {
        return reply.code(409).send({ error: "already_resolved", message: "this request was already resolved on-chain" });
      }
      throw err;
    }
  });

  app.post<{ Params: { id: string } }>("/approvals/:id/reject", gasSpendingRoute, async (req, reply) => {
    if (!req.operator) return reply.code(500).send({ error: "internal_error", message: "operator identity missing" });

    const requestId = BigInt(req.params.id);
    try {
      const hash = await serializeTx("approver", async () => {
        await ensureUnresolved(requestId);
        return spendGuard.approver.write.rejectPending([requestId]);
      });
      await recordOperatorAction(req.operator, "reject", req.params.id, hash);
      broadcast({ type: "approval_resolved", requestId: req.params.id, decision: "rejected", txHash: hash, by: req.operator.id });
      return reply.send({ txHash: hash });
    } catch (err) {
      if (err instanceof AlreadyResolvedError) {
        return reply.code(409).send({ error: "already_resolved", message: "this request was already resolved on-chain" });
      }
      throw err;
    }
  });
}

/// The on-chain AuditLog records that an approval happened; it has no
/// concept of the human who triggered it. This is the server-side half of
/// the audit trail: who (which credential) resolved which request, with the
/// tx hash tying the two records together. Written *after* the tx succeeds,
/// so it can never claim an action that didn't happen on-chain.
async function recordOperatorAction(
  operator: { id: string; label: string; role: string },
  action: string,
  subjectId: string,
  txHash: string,
) {
  await prisma.operatorAction.create({
    data: {
      operatorId: operator.id,
      operatorLabel: operator.label,
      role: operator.role,
      action,
      subjectId,
      txHash,
    },
  });
}