import { prisma } from "../db/client.js";
import { broadcastEvent } from "../ws/broadcast.js";
import { startWatcher, type ProcessableLog } from "./runner.js";
import { spendGuardAbi } from "../chain/abis/spendGuard.js";
import { deploymentKey, listServedDeployments, type Deployment } from "../chain/orgContracts.js";

/// Canonical indexer-checkpoint name for a payment watcher on a deployment.
/// Shared with route code that reads lag (approvals queue) so a rename can
/// never silently split writers from readers.
export function paymentCheckpointName(deploymentKey: string, event: string): string {
  return deploymentKey === "global" ? `payments:${event}` : `org:${deploymentKey}:payments:${event}`;
}

/// Subscribes to every payment-lifecycle event a SpendGuard deployment
/// emits, writes each one to the `events` table via Prisma, keeps
/// `agents.spentToday` and `pending_requests` in sync, and pushes a live
/// update over WebSocket so the flow view doesn't need to poll.
///
/// One watcher set per served deployment: the server's global deployment
/// always, plus every org's mainnet deployment in mainnet mode (see
/// server.ts boot and orgContracts.listServedDeployments). Every DB write
/// is scoped by deploymentKey — on-chain request ids are per-deployment
/// counters, so rows for different deployments must never mix.
///
/// Processing runs through indexer/runner.ts: idempotent per (deployment,
/// tx, log index), checkpointed per deployment, backfilled on restart.
export async function watchPaymentEventsFor(deployment: Deployment): Promise<void> {
  const key = deploymentKey(deployment);
  // The events table has no deployment column: agents are globally unique
  // addresses, so event rows stay keyed by agent alone.
  const watcherName = (event: string) => paymentCheckpointName(key, event);

  const watchers = [
    {
      name: watcherName("PaymentApproved"),
      eventName: "PaymentApproved",
      onLog: async ({ args, transactionHash }: ProcessableLog) => {
        const { requestId, agent, counterparty, amount } = args as {
          requestId?: bigint; agent?: string; counterparty?: string; amount?: bigint;
        };
        const amt = amount ?? 0n;

        await prisma.event.create({
          data: { agent: agent!, counterparty: counterparty!, amount: amt, decision: "approved", txHash: transactionHash },
        });
        await upsertAgentSpend(agent!, amt);
        // requestId is 0 for payments that settled immediately (no
        // escalation ever happened, so there's nothing pending to resolve).
        if (requestId && requestId > 0n) {
          await prisma.pendingRequest.updateMany({
            where: { deploymentKey: key, requestId },
            data: { resolved: true },
          });
        }
        broadcastEvent({ type: "payment_approved", agent, counterparty, amount: amt.toString() }, deployment);
      },
    },
    {
      name: watcherName("PaymentBlocked"),
      eventName: "PaymentBlocked",
      onLog: async ({ args, transactionHash }: ProcessableLog) => {
        const { agent, counterparty, amount, reason } = args as {
          agent?: string; counterparty?: string; amount?: bigint; reason?: string;
        };
        const amt = amount ?? 0n;

        await prisma.event.create({
          data: { agent: agent!, counterparty: counterparty!, amount: amt, decision: `blocked: ${reason}`, txHash: transactionHash },
        });
        broadcastEvent({ type: "payment_blocked", agent, counterparty, amount: amt.toString(), reason }, deployment);
      },
    },
    {
      name: watcherName("PaymentEscalated"),
      eventName: "PaymentEscalated",
      onLog: async ({ args, transactionHash }: ProcessableLog) => {
        const { requestId, agent, counterparty, amount } = args as {
          requestId?: bigint; agent?: string; counterparty?: string; amount?: bigint;
        };
        const amt = amount ?? 0n;

        await prisma.event.create({
          data: { agent: agent!, counterparty: counterparty!, amount: amt, decision: "escalated", txHash: transactionHash },
        });
        await prisma.pendingRequest.upsert({
          where: {
            deploymentKey_requestId: { deploymentKey: key, requestId: requestId! },
          },
          create: {
            deploymentKey: key,
            requestId: requestId!,
            agent: agent!,
            counterparty: counterparty!,
            amount: amt,
            resolved: false,
          },
          update: {},
        });
        broadcastEvent({ type: "payment_escalated", requestId: requestId?.toString(), agent, counterparty, amount: amt.toString() }, deployment);
      },
    },
    {
      name: watcherName("PendingApproved"),
      eventName: "PendingApproved",
      onLog: async ({ args }: ProcessableLog) => {
        const { requestId, approver } = args as { requestId?: bigint; approver?: string };
        // The chain event names only the approver; the agent comes from the
        // indexed row so agent-scoped WS subscribers receive this too.
        // Read BEFORE resolving: the row survives (resolved=true) but reading
        // first keeps the broadcast's agent unambiguous about when it was set.
        const row = await prisma.pendingRequest.findUnique({
          where: { deploymentKey_requestId: { deploymentKey: key, requestId: requestId! } },
        });
        await prisma.pendingRequest.updateMany({
          where: { deploymentKey: key, requestId: requestId! },
          data: { resolved: true },
        });
        broadcastEvent({ type: "approval_resolved", requestId: requestId?.toString(), decision: "approved", approver, agent: row?.agent }, deployment);
      },
    },
    {
      name: watcherName("PendingRejected"),
      eventName: "PendingRejected",
      onLog: async ({ args }: ProcessableLog) => {
        const { requestId, approver } = args as { requestId?: bigint; approver?: string };
        // Same agent lookup as PendingApproved above.
        const row = await prisma.pendingRequest.findUnique({
          where: { deploymentKey_requestId: { deploymentKey: key, requestId: requestId! } },
        });
        await prisma.pendingRequest.updateMany({
          where: { deploymentKey: key, requestId: requestId! },
          data: { resolved: true },
        });
        broadcastEvent({ type: "approval_resolved", requestId: requestId?.toString(), decision: "rejected", approver, agent: row?.agent }, deployment);
      },
    },
  ];

  await Promise.all(
    watchers.map((w) =>
      startWatcher({
        name: w.name,
        address: deployment.spendGuard,
        abi: spendGuardAbi,
        eventName: w.eventName,
        client: deployment.publicClient,
        onLog: w.onLog,
      }),
    ),
  );
}

/// Keep `agents.spentToday` in sync with PaymentApproved events. The indexer
/// writes through the agents table; PolicyRegistry — not the agent row —
/// remains the read-time source of truth (see routes/agents.ts), so this
/// counter is best-effort bookkeeping. When a per-org deployment indexes an
/// agent that has no row yet, one is created with zeroed caps: the caps are
/// backfilled by the next PolicySet/AllowlistUpdated event or the live chain
/// read in /agents, never invented here.
async function upsertAgentSpend(agent: string, amt: bigint) {
  try {
    await prisma.agent.update({
      where: { address: agent.toLowerCase() },
      data: { spentToday: { increment: amt } },
    });
  } catch {
    await prisma.agent.upsert({
      where: { address: agent.toLowerCase() },
      create: {
        address: agent.toLowerCase(),
        dailyCap: 0n,
        perTxCap: 0n,
        escalationThreshold: 0n,
        spentToday: 0n,
        status: "active",
      },
      update: { spentToday: { increment: amt } },
    });
  }
}

/// Index payment events for every served deployment (global always; per-org
/// mainnet deployments in mainnet mode).
export async function watchPaymentEvents(): Promise<void> {
  const deployments = await listServedDeployments();
  await Promise.all(deployments.map((deployment) => watchPaymentEventsFor(deployment)));
}
