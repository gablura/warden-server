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

export async function approvalRoutes(app: FastifyInstance) {
  app.get("/approvals", async () => {
    const pending = await prisma.pendingRequest.findMany({
      where: { resolved: false },
      orderBy: { createdAt: "asc" },
    });
    return serializeBigInts(pending);
  });

  app.post<{ Params: { id: string } }>("/approvals/:id/approve", gasSpendingRoute, async (req, reply) => {
    const requestId = BigInt(req.params.id);
    const hash = await spendGuard.approver.write.approvePending([requestId]);
    broadcast({ type: "approval_resolved", requestId: req.params.id, decision: "approved", txHash: hash });
    return reply.send({ txHash: hash });
  });

  app.post<{ Params: { id: string } }>("/approvals/:id/reject", gasSpendingRoute, async (req, reply) => {
    const requestId = BigInt(req.params.id);
    const hash = await spendGuard.approver.write.rejectPending([requestId]);
    broadcast({ type: "approval_resolved", requestId: req.params.id, decision: "rejected", txHash: hash });
    return reply.send({ txHash: hash });
  });
}