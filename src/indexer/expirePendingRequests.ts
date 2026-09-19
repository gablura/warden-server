import { prisma } from "../db/client.js";
import { broadcastEvent } from "../ws/broadcast.js";
import { RESERVATION_TTL_SECONDS, listServedDeployments, type Deployment } from "../chain/orgContracts.js";

/// Expiry handling for the approvals lifecycle (AGENTS_APPROVALS_AUDIT_
/// OVERVIEW.md §Approvals 6): a pending request whose escalation
/// reservation has passed its reservedUntil must be rejected EXPLICITLY —
/// "expired — no approver action within window" — instead of silently
/// losing its reservation while staying ambiguously "pending" forever.
///
/// The chain frees the reserved headroom lazily (PolicyRegistry ignores
/// reservation values at the day boundary and approvePending's require is
/// the final arbiter), so this sweeper is the bookkeeping half: it moves
/// the DB row to resolved, writes the audit Event row, and pushes the
/// resolution over WebSocket — the same three writes an approver's reject
/// produces, so the audit trail records what actually happened.
///
/// Implementation choice (per the implementation prompt: "pick one and
/// make it consistent"): a scheduled interval, NOT a lazy check on queue
/// reads. Reasons: read-path expiry would make GET /approvals mutate state
/// (surprising for a poller, and it would run on every anonymous read),
/// while a single interval under the indexer's advisory lock runs exactly
/// once per fleet no matter how many replicas poll the queue.

/// One expiry sweep across every served deployment. Runs under the indexer
/// lock, so no cross-replica contention; rows are claimed per-deployment.
export async function expirePendingRequests(): Promise<number> {
  const deployments = await listServedDeployments();
  let total = 0;
  for (const deployment of deployments) {
    total += await expireForDeployment(deployment);
  }
  return total;
}

/// Rejections recorded in the audit trail use this exact string — the
/// spec'd wording, and the marker /approvals readers can rely on.
export const EXPIRED_REJECT_REASON = "expired — no approver action within window";

async function expireForDeployment(deployment: Deployment): Promise<number> {
  const key = deployment.orgId ?? "global";
  const now = new Date();

  // Candidate batch: unresolved rows whose expiry has passed. expiresAt is
  // stamped by the SpendReserved indexer (see watchPolicyEvents.ts); rows
  // indexed before that column existed fall back to createdAt + TTL, which
  // matches the on-chain reserve() arithmetic exactly.
  const overdue = await prisma.pendingRequest.findMany({
    where: {
      deploymentKey: key,
      resolved: false,
      OR: [
        { expiresAt: { not: null, lte: now } },
        { expiresAt: null, createdAt: { lte: new Date(now.getTime() - RESERVATION_TTL_SECONDS * 1000) } },
      ],
    },
    take: 100,
    orderBy: { createdAt: "asc" },
  });

  for (const row of overdue) {
    // Claim first, then write: the updateMany is guarded by resolved=false,
    // so even if two sweeps raced (they can't under the lock, but stay
    // cheap about it), only one row transition happens and the loser
    // updates zero rows. The chain side needs no transaction: releasing an
    // already-expired reservation is a no-op on the registry (see
    // SpendGuard.approvePending's comment), so we never pay gas here.
    const claimed = await prisma.pendingRequest.updateMany({
      where: { deploymentKey: key, requestId: row.requestId, resolved: false },
      data: { resolved: true },
    });
    if (claimed.count === 0) continue;

    await prisma.event.create({
      data: {
        agent: row.agent,
        counterparty: row.counterparty,
        amount: row.amount,
        decision: EXPIRED_REJECT_REASON,
        txHash: "",
      },
    });

    broadcastEvent(
      {
        type: "approval_resolved",
        requestId: row.requestId.toString(),
        decision: "rejected",
        agent: row.agent,
        reason: EXPIRED_REJECT_REASON,
      },
      deployment,
    );
  }

  return overdue.length;
}

/// Fixed cadence. TTL is 7 days, so precision barely matters; 60s keeps a
/// restarted server's backlog sweep prompt without hammering the DB.
export const EXPIRY_SWEEP_INTERVAL_MS = 60_000;

/// Long-running loop. Never throws — a failed sweep logs and retries on the
/// next tick, because expiry bookkeeping must not take the server down.
export function startExpirySweeper(log: {
  info: (msg: string) => void;
  error: (msg: string, err?: unknown) => void;
}): void {
  const tick = async () => {
    try {
      const n = await expirePendingRequests();
      if (n > 0) log.info(`Expired ${n} pending request(s) past their reservation window`);
    } catch (err) {
      log.error("Expiry sweep failed — will retry next tick", err);
    }
  };
  void tick();
  setInterval(tick, EXPIRY_SWEEP_INTERVAL_MS).unref();
}