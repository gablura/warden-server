import type { FastifyInstance } from "fastify";
import { prisma, serializeBigInts } from "../db/client.js";
import { publicClient } from "../chain/client.js";
import { spendGuardAbi } from "../chain/abis/spendGuard.js";
import { readAgentPolicies } from "../chain/policyState.js";
import { deploymentKey, resolveDeployment, resolveDeploymentForAgent, type Deployment } from "../chain/orgContracts.js";
import { paymentCheckpointName } from "../indexer/watchPaymentEvents.js";
import { GrantMissingError, submitAsApprover, type SigningResult } from "../chain/signing.js";
import { broadcastEvent } from "../ws/broadcast.js";
import { requireRole, optionalAuth } from "../auth/clerkAuth.js";
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
/// from the indexed PendingRequest row (scoped to the request's deployment —
/// request ids are per-deployment counters); if the row hasn't been indexed
/// yet the scope check passes, because failing closed here would let an
/// indexer lag make *all* approvals impossible, and the ceiling is a scoping
/// refinement, not the daily-cap enforcement (which lives on-chain).
async function withinApprovalScope(deploymentKey: string, requestId: bigint, operatorMaxApproval: bigint | undefined) {
  if (operatorMaxApproval === undefined) return;
  const pending = await prisma.pendingRequest.findUnique({
    where: { deploymentKey_requestId: { deploymentKey, requestId } },
  });
  if (!pending) return; // see comment above
  if (pending.amount > operatorMaxApproval) {
    throw new Error(`approval amount exceeds this credential's maxApproval ceiling`);
  }
}

/// Approval ids are on-chain uint256 counters arriving as URL strings.
/// Parsing here (once, at the route boundary) turns a malformed id into a
/// cheap 400 instead of an unhandled BigInt SyntaxError surfacing as a 500.
function parseRequestId(raw: string): bigint | null {
  if (!/^\d+$/.test(raw)) return null;
  try {
    return BigInt(raw);
  } catch {
    return null; // unreachable given the regex, kept for safety
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

/// Locate the deployment holding a request.
///
/// Request ids are per-deployment on-chain counters, so resolution goes:
///   1. An indexed row under the operator's org deployment key (their org's
///      mainnet contracts) — the common mainnet case.
///   2. An indexed row under the global key, resolved through the agent's
///      org mapping (the historical single-deployment path).
///   3. Chain probing of the operator's org deployment, then the global
///      one — the first where the request exists (non-zero agent) wins.
///      This also covers rows not indexed yet.
///
/// Without org context (service approvers), only the global key/probe is
/// considered: there is no basis to guess which org deployment to consult.
/// Returns null when the request lives on no served deployment.
async function findRequestDeployment(
  requestId: bigint,
  operatorOrgId?: string,
): Promise<{ deployment: Deployment; agent: string } | null> {
  if (operatorOrgId) {
    const orgRow = await prisma.pendingRequest.findUnique({
      where: { deploymentKey_requestId: { deploymentKey: operatorOrgId, requestId } },
    });
    if (orgRow) {
      return { deployment: await resolveDeployment(operatorOrgId), agent: orgRow.agent };
    }
  }

  const globalRow = await prisma.pendingRequest.findUnique({
    where: { deploymentKey_requestId: { deploymentKey: "global", requestId } },
  });
  if (globalRow) {
    return { deployment: await resolveDeploymentForAgent(globalRow.agent), agent: globalRow.agent };
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
  // The queue is tenant-scoped when credentials are presented (see the
  // deployment-resolution note below) and keeps an anonymous view for
  // service/monitoring callers — but PRESENTED credentials are always
  // verified: a bad key gets a 401, never a silent downgrade to anonymous.
  app.get<{ Querystring: { limit?: string } }>("/approvals", { preHandler: optionalAuth() }, async (req) => {
    const { limit } = limitQuerySchema.parse(req.query);

    // The queue view is deployment-scoped. Org members (Clerk + scoped
    // tokens always carry an orgId — see clerkAuth) see their org's own
    // mainnet deployment queue; callers without org context (service
    // credentials, anonymous viewers) see the global deployment's queue.
    // resolveDeployment keeps testnet pinned to global, and the chain read
    // comes from the SAME deployment so lag is measured against the right
    // chain. The queue is fed by the per-deployment indexers started in
    // server.ts (see orgContracts.listServedDeployments).
    const deployment = await resolveDeployment(req.operator?.orgId);
    const key = deploymentKey(deployment);

    // Fetch pending requests, indexer checkpoint, and chain head in parallel.
    // The checkpoint tells us how far behind the indexer is; if it's lagging,
    // some "pending" requests may already be resolved on-chain — the staleRead
    // flag surfaces this so the frontend can warn before a wasted-gas revert.
    const [result, checkpoint, chainHead] = await Promise.all([
      paginatedQuery(
        (take) =>
          prisma.pendingRequest.findMany({
            where: { deploymentKey: key, resolved: false },
            orderBy: { createdAt: "asc" },
            take,
          }),
        limit,
      ),
      prisma.indexerCheckpoint.findUnique({
        where: { watcher: paymentCheckpointName(key, "PaymentApproved") },
      }),
      deployment.publicClient.getBlockNumber().catch(() => 0n),
    ]);

    const indexerLag = checkpoint ? Number(chainHead - checkpoint.lastBlock) : null;
    const staleRead = indexerLag !== null && indexerLag > 0;

    // Make the daily-cap collision visible before anyone clicks approve.
    // On-chain, an escalated request RESERVES its headroom at escalation
    // time (PolicyRegistry.reserve) and the reservation converts into real
    // spend at approval (approvePending releases, then recordSpend).
    // "Would this still fit" is therefore a question about the agent's
    // total committed headroom — spend plus all live reservations — not
    // about this request in isolation: approving it merely converts its
    // own reservation into spend, so the amount cancels out of the
    // inequality and `committed <= dailyCap` is the exact state
    // recordSpend's require enforces once this request's reservation is
    // released. It stops fitting when circumstances changed after
    // queueing: a cap decrease (applies immediately), direct unescalated
    // spend, or expiry handling freeing the reservation. Both sides come
    // from the same reservation-aware chain snapshot (see policyState.ts)
    // — the old spentToday-only check ignored reservations entirely.
    const agents = [...new Set(result.data.map((r) => r.agent))];
    const policies = await readAgentPolicies(agents);
    const policyByAgent = new Map(agents.map((agent, i) => [agent, policies[i]!]));

    const enriched = result.data.map((request) => {
      const policy = policyByAgent.get(request.agent)!;
      return {
        ...request,
        remainingToday: policy.remainingToday,
        policyExists: policy.exists,
        // False can mean "doesn't fit" *or* "policy unreadable" — the
        // exists/policySource flags distinguish the two for clients.
        wouldFitNow: policy.exists && policy.spentToday + policy.activeReserved <= policy.dailyCap,
      };
    });

    return serializeBigInts({ data: enriched, hasMore: result.hasMore, staleRead, indexerLag });
  });

  async function resolveRequest(
    requestId: bigint,
    operator: { id: string; orgId?: string },
    operatorMaxApproval: bigint | undefined,
    decision: "approvePending" | "rejectPending",
  ): Promise<{ signing: SigningResult; deployment: Deployment; agent: string }> {
    const found = await findRequestDeployment(requestId, operator.orgId);
    if (!found) {
      throw Object.assign(new Error("no such pending request on any served deployment"), { statusCode: 404, code: "not_found" });
    }
    const { deployment } = found;

    // Scoped INSIDE the resolution: the ceiling applies to the deployment
    // the request actually lives on, whose indexed row carries the amount.
    await withinApprovalScope(deploymentKey(deployment), requestId, operatorMaxApproval);

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

    const requestId = parseRequestId(req.params.id);
    if (requestId === null) {
      return reply.code(400).send({ error: "invalid_request", message: "approval id must be a non-negative integer" });
    }      try {
      const { signing, agent, deployment } = await resolveRequest(requestId, req.operator, req.operator.maxApproval, "approvePending");
      await recordOperatorAction(req.operator, "approve", requestId.toString(), signing.txHash, signing);
      broadcastEvent({ type: "approval_resolved", requestId: requestId.toString(), decision: "approved", txHash: signing.txHash, by: req.operator.id, agent }, deployment);
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

    const requestId = parseRequestId(req.params.id);
    if (requestId === null) {
      return reply.code(400).send({ error: "invalid_request", message: "approval id must be a non-negative integer" });
    }

    try {
      const { signing, agent, deployment } = await resolveRequest(requestId, req.operator, req.operator.maxApproval, "rejectPending");
      await recordOperatorAction(req.operator, "reject", requestId.toString(), signing.txHash, signing);
      broadcastEvent({ type: "approval_resolved", requestId: requestId.toString(), decision: "rejected", txHash: signing.txHash, by: req.operator.id, agent }, deployment);
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
