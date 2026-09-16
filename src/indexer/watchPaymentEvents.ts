import { config } from "../config.js";
import { prisma } from "../db/client.js";
import { broadcast } from "../ws/broadcast.js";
import { startWatcher, type ProcessableLog } from "./runner.js";
import { spendGuardAbi } from "../chain/abis/spendGuard.js";

/// Subscribes to every payment-lifecycle event SpendGuard emits, writes
/// each one to the `events` table via Prisma, keeps `agents.spentToday`
/// and `pending_requests` in sync, and pushes a live update over
/// WebSocket so the flow view doesn't need to poll.
///
/// Processing runs through indexer/runner.ts: idempotent per (tx, log
/// index), checkpointed, and backfilled on restart — see that module for
/// why each handler below does no dedup of its own.
export async function watchPaymentEvents(): Promise<void> {
  const address = config.SPEND_GUARD_ADDRESS as `0x${string}`;

  const watchers = [
    {
      name: "payments:PaymentApproved",
      eventName: "PaymentApproved",
      onLog: async ({ args, transactionHash }: ProcessableLog) => {
        const { requestId, agent, counterparty, amount } = args as {
          requestId?: bigint; agent?: string; counterparty?: string; amount?: bigint;
        };
        const amt = amount ?? 0n;

        await prisma.event.create({
          data: { agent: agent!, counterparty: counterparty!, amount: amt, decision: "approved", txHash: transactionHash },
        });
        await prisma.agent.update({
          where: { address: agent! },
          data: { spentToday: { increment: amt } },
        });
        // requestId is 0 for payments that settled immediately (no
        // escalation ever happened, so there's nothing pending to resolve).
        if (requestId && requestId > 0n) {
          await prisma.pendingRequest.updateMany({ where: { requestId }, data: { resolved: true } });
        }
        broadcast({ type: "payment_approved", agent, counterparty, amount: amt.toString() });
      },
    },
    {
      name: "payments:PaymentBlocked",
      eventName: "PaymentBlocked",
      onLog: async ({ args, transactionHash }: ProcessableLog) => {
        const { agent, counterparty, amount, reason } = args as {
          agent?: string; counterparty?: string; amount?: bigint; reason?: string;
        };
        const amt = amount ?? 0n;

        await prisma.event.create({
          data: { agent: agent!, counterparty: counterparty!, amount: amt, decision: `blocked: ${reason}`, txHash: transactionHash },
        });
        broadcast({ type: "payment_blocked", agent, counterparty, amount: amt.toString(), reason });
      },
    },
    {
      name: "payments:PaymentEscalated",
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
          where: { requestId: requestId! },
          create: { requestId: requestId!, agent: agent!, counterparty: counterparty!, amount: amt, resolved: false },
          update: {},
        });
        broadcast({ type: "payment_escalated", requestId: requestId?.toString(), agent, counterparty, amount: amt.toString() });
      },
    },
    {
      name: "payments:PendingApproved",
      eventName: "PendingApproved",
      onLog: async ({ args }: ProcessableLog) => {
        const { requestId, approver } = args as { requestId?: bigint; approver?: string };
        // The chain event names only the approver; the agent comes from the
        // indexed row so agent-scoped WS subscribers receive this too.
        // Read BEFORE resolving: the row survives (resolved=true) but reading
        // first keeps the broadcast's agent unambiguous about when it was set.
        const row = await prisma.pendingRequest.findUnique({ where: { requestId: requestId! } });
        await prisma.pendingRequest.updateMany({ where: { requestId: requestId! }, data: { resolved: true } });
        broadcast({ type: "approval_resolved", requestId: requestId?.toString(), decision: "approved", approver, agent: row?.agent });
      },
    },
    {
      name: "payments:PendingRejected",
      eventName: "PendingRejected",
      onLog: async ({ args }: ProcessableLog) => {
        const { requestId, approver } = args as { requestId?: bigint; approver?: string };
        // Same agent lookup as PendingApproved above.
        const row = await prisma.pendingRequest.findUnique({ where: { requestId: requestId! } });
        await prisma.pendingRequest.updateMany({ where: { requestId: requestId! }, data: { resolved: true } });
        broadcast({ type: "approval_resolved", requestId: requestId?.toString(), decision: "rejected", approver, agent: row?.agent });
      },
    },
  ];

  await Promise.all(
    watchers.map((w) =>
      startWatcher({ name: w.name, address, abi: spendGuardAbi, eventName: w.eventName, onLog: w.onLog }),
    ),
  );
}