import type { FastifyInstance } from "fastify";
import { prisma, serializeBigInts } from "../db/client.js";
import { spendGuard } from "../chain/client.js";
import { broadcast } from "../ws/broadcast.js";
import { requireRole } from "../auth/apiKeyAuth.js";

// Same shape as policies.ts's gas-spending routes — approver key required,
// tight rate limit, since these send real transactions.
const gasSpendingRoute = {
  preHandler: requireRole("approver"),
  config: { rateLimit: { max: 20, timeWindow: "1 minute" } },
};

/// Per-credential approval scoping. An approver credential may declare a
/// maxApproval ceiling (in base units); requests above it are refused before
/// any transaction is signed. The amount comes from the indexed
/// PendingRequest row; if the row hasn't been indexed yet the scope check
/// passes, because failing closed here would let an indexer lag make *all*
/// approvals impossible, and the ceiling is a scoping refinement, not the
/// daily-cap enforcement (which lives on-chain in recordSpend).
async function withinApprovalScope(requestId: bigint, operatorMaxApproval: bigint | undefined) {
  if (operatorMaxApproval === undefined) return;
  const pending = await prisma.pendingRequest.findUnique({ where: { requestId } });
  if (!pending) return; // see comment above
  if (pending.amount > operatorMaxApproval) {
    throw new Error(`approval amount exceeds this credential's maxApproval ceiling`);
  }
}

export async function approvalRoutes(app: FastifyInstance) {
  app.get("/approvals", async () => {
    const pending = await prisma.pendingRequest.findMany({
      where: { resolved: false },
      orderBy: { createdAt: "asc" },
    });
    return serializeBigInts(pending);
  });

  app.post<{ Params: { id: string } }>("/approvals/:id/approve", gasSpendingRoute, async (req, reply) => {
    // The preHandler guarantees req.operator is set; this guard keeps the
    // handler honest if the middleware wiring ever changes.
    if (!req.operator) return reply.code(500).send({ error: "internal_error", message: "operator identity missing" });

    const requestId = BigInt(req.params.id);
    await withinApprovalScope(requestId, req.operator.maxApproval);

    const hash = await spendGuard.approver.write.approvePending([requestId]);
    await recordOperatorAction(req.operator, "approve", req.params.id, hash);
    broadcast({ type: "approval_resolved", requestId: req.params.id, decision: "approved", txHash: hash, by: req.operator.id });
    return reply.send({ txHash: hash });
  });

  app.post<{ Params: { id: string } }>("/approvals/:id/reject", gasSpendingRoute, async (req, reply) => {
    if (!req.operator) return reply.code(500).send({ error: "internal_error", message: "operator identity missing" });

    const requestId = BigInt(req.params.id);
    const hash = await spendGuard.approver.write.rejectPending([requestId]);
    await recordOperatorAction(req.operator, "reject", req.params.id, hash);
    broadcast({ type: "approval_resolved", requestId: req.params.id, decision: "rejected", txHash: hash, by: req.operator.id });
    return reply.send({ txHash: hash });
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