import type { FastifyInstance } from "fastify";
import { prisma, serializeBigInts } from "../db/client.js";
import { publicClient } from "../chain/client.js";
import { spendGuardAbi } from "../chain/abis/spendGuard.js";
import { readAgentPolicies } from "../chain/policyState.js";
import { resolveDeployment, resolveDeploymentForAgent, type Deployment } from "../chain/orgContracts.js";
import { GrantMissingError, submitAsApprover, type SigningResult } from "../chain/signing.js";
import { broadcast } from "../ws/broadcast.js";
import { requireRole } from "../auth/clerkAuth.js";
import { productionGate } from "../auth/productionGate.js";
import { limitQuerySchema, paginatedQuery } from "../db/pagination.js";
import { getCorrelationId } from "../auth/correlation.js";

// Same shape as policies.ts's gas-spending routes — approver role required,
// production gate enforced, tight rate limit, since these send real
// transactions. The tx itself is signed by the acting person's embedded
// wallet via Circle when available (see signing.ts), one tap, no gas popup.
const gasSpendingRoute = {
  preHandler: [requireRole("approver"), productionGate()],
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

type PendingRow = readonly [`0x${string}`, `0x${string}`, bigint, boolean];

async function readPending(deployment: Deployment, requestId: bigint): Promise<PendingRow> {
  return deployment.publicClient.readContract({
    address: deployment.spendGuard,
    abi: spendGuardAbi,
    functionName: "pending",
    args: [requestId],
  }) as Promise<PendingRow>;
}

/// Locate the deployment holding a request. The indexed row names the agent
/// directly; otherwise probe the operator's org deployment first, then the
/// global one, and take the first where the request exists (non-zero
/// agent). Returns null when the request lives on no served deployment.
async function findRequestDeployment(
  requestId: bigint,
  operatorOrgId?: string,
): Promise<{ deployment: Deployment; agent: string } | null> {
  const row = await prisma.pendingRequest.findUnique({ where: { requestId } });
  if (row) {
    return { deployment: await resolveDeploymentForAgent(row.agent), agent: row.agent };
  }

  const candidates: Deployment[] = [];
  if (operatorOrgId) {
    const orgDeployment = await resolveDeployment(operatorOrgId);
    candidates.push(orgDeployment);
  }
  const global = await resolveDeployment(null);
  if (!candidates.some((d) => d.chainId === global.chainId && d.spendGuard === global.spendGuard)) {
    candidates.push(global);
  }

  for (const deployment of candidates) {
    const pending = await readPending(deployment, requestId);
    // pending() returns (agent, counterparty, amount, resolved) in
    // declaration order. A zero agent means "no such request here".
    if (pending[0] !== "0x0000000000000000000000000000000000000000") {
      return { deployment, agent: pending[0] };
    }
  }
  return null;
}

async function ensureUnresolvedOn(deployment: Deployment, requestId: bigint) {
  const pending = await readPending(deployment, requestId);
  if (pending[3]) throw new AlreadyResolvedError();
}

export async function approvalRoutes(app: FastifyInstance) {
  app.get<{ Querystring: { limit?: string } }>("/approvals", async (req) => {
    const { limit } = limitQuerySchema.parse(req.query);

    // Fetch pending requests, indexer checkpoint, and chain head in parallel.
    // The checkpoint tells us how far behind the indexer is; if it's lagging,
    // some "pending" requests may already be resolved on-chain — the staleRead
    // flag surfaces this so the frontend can warn before a wasted-gas revert.
    // NOTE: the queue view covers the server's connected (global) deployment;
    // per-org mainnet deployments are written through this API but indexed by
    // dedicated per-deployment instances (see orgContracts.ts).
    const [result, checkpoint, chainHead] = await Promise.all([
      paginatedQuery(
        (take) =>
          prisma.pendingRequest.findMany({
            where: { resolved: false },
            orderBy: { createdAt: "asc" },
            take,
          }),
        limit,
      ),
      prisma.indexerCheckpoint.findUnique({ where: { watcher: "payments:PaymentApproved" } }),
      publicClient.getBlockNumber().catch(() => 0n),
    ]);

    const indexerLag = checkpoint ? Number(chainHead - checkpoint.lastBlock) : null;
    const staleRead = indexerLag !== null && indexerLag > 0;

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

    return serializeBigInts({ data: enriched, hasMore: result.hasMore, staleRead, indexerLag });
  });

  async function resolveRequest(
    reqId: string,
    operator: { id: string; orgId?: string },
    decision: "approvePending" | "rejectPending",
  ): Promise<{ signing: SigningResult; deployment: Deployment; agent: string }> {
    const requestId = BigInt(reqId);
    const found = await findRequestDeployment(requestId, operator.orgId);
    if (!found) {
      throw Object.assign(new Error("no such pending request on any served deployment"), { statusCode: 404, code: "not_found" });
    }
    const { deployment } = found;

    const signature = decision === "approvePending" ? "approvePending(uint256)" : "rejectPending(uint256)";
    try {
      const signing = await submitAsApprover({
        operatorId: operator.id,
        deployment,
        functionName: decision,
        functionSignature: signature,
        requestArgs: [requestId],
        ensureUnresolved: () => ensureUnresolvedOn(deployment, requestId),
      });
      return { signing, deployment, agent: found.agent };
    } catch (err) {
      if (err instanceof AlreadyResolvedError) throw err;
      // A late failure (e.g. Circle reports FAILED after a race): re-read
      // before answering, so a request resolved in the meantime is a 409
      // rather than a 503.
      if (err instanceof GrantMissingError) throw err;
      try {
        await ensureUnresolvedOn(deployment, requestId);
      } catch (reread) {
        if (reread instanceof AlreadyResolvedError) throw reread;
      }
      throw err;
    }
  }

  app.post<{ Params: { id: string } }>("/approvals/:id/approve", gasSpendingRoute, async (req, reply) => {
    // The preHandler guarantees req.operator is set; this guard keeps the
    // handler honest if the middleware wiring ever changes.
    if (!req.operator) return reply.code(500).send({ error: "internal_error", message: "operator identity missing" });

    await withinApprovalScope(BigInt(req.params.id), req.operator.maxApproval);

    try {
      const { signing } = await resolveRequest(req.params.id, req.operator, "approvePending");
      await recordOperatorAction(req.operator, "approve", req.params.id, signing.txHash, signing);
      broadcast({ type: "approval_resolved", requestId: req.params.id, decision: "approved", txHash: signing.txHash, by: req.operator.id });
      return reply.send({ txHash: signing.txHash, signer: signing.signer, via: signing.via, correlationId: req.correlationId });
    } catch (err) {
      if (err instanceof AlreadyResolvedError) {
        return reply.code(409).send({ error: "already_resolved", message: "this request was already resolved on-chain" });
      }
      if (err instanceof GrantMissingError) {
        return reply.code(403).send({ error: "onchain_grant_missing", message: err.message });
      }
      const statusCode = (err as { statusCode?: unknown }).statusCode;
      const code = (err as { code?: unknown }).code;
      if (statusCode === 404 && code === "not_found") {
        return reply.code(404).send({ error: "not_found", message: "no such pending request" });
      }
      throw err;
    }
  });

  app.post<{ Params: { id: string } }>("/approvals/:id/reject", gasSpendingRoute, async (req, reply) => {
    if (!req.operator) return reply.code(500).send({ error: "internal_error", message: "operator identity missing" });

    try {
      const { signing } = await resolveRequest(req.params.id, req.operator, "rejectPending");
      await recordOperatorAction(req.operator, "reject", req.params.id, signing.txHash, signing);
      broadcast({ type: "approval_resolved", requestId: req.params.id, decision: "rejected", txHash: signing.txHash, by: req.operator.id });
      return reply.send({ txHash: signing.txHash, signer: signing.signer, via: signing.via, correlationId: req.correlationId });
    } catch (err) {
      if (err instanceof AlreadyResolvedError) {
        return reply.code(409).send({ error: "already_resolved", message: "this request was already resolved on-chain" });
      }
      if (err instanceof GrantMissingError) {
        return reply.code(403).send({ error: "onchain_grant_missing", message: err.message });
      }
      const statusCode = (err as { statusCode?: unknown }).statusCode;
      const code = (err as { code?: unknown }).code;
      if (statusCode === 404 && code === "not_found") {
        return reply.code(404).send({ error: "not_found", message: "no such pending request" });
      }
      throw err;
    }
  });
}

/// The on-chain AuditLog records that an approval happened; it has no
/// concept of the human who triggered it. This is the server-side half of
/// the audit trail: who (which person, which wallet, which signing key)
/// resolved which request, with the tx hash tying the two records together.
/// Written *after* the tx succeeds, so it can never claim an action that
/// didn't happen on-chain.
async function recordOperatorAction(
  operator: { id: string; label: string; role: string; walletAddress?: string },
  action: string,
  subjectId: string,
  txHash: string,
  signing: SigningResult,
) {
  await prisma.operatorAction.create({
    data: {
      operatorId: operator.id,
      operatorLabel: operator.label,
      role: operator.role,
      action,
      subjectId,
      txHash,
      correlationId: getCorrelationId() ?? null,
      walletAddress: operator.walletAddress ?? null,
      signerAddress: signing.signer,
      signingVia: signing.via,
    },
  });
}
