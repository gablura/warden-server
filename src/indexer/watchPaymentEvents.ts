import { publicClient } from "../chain/client.js";
import { config } from "../config.js";
import { prisma } from "../db/client.js";
import { broadcast } from "../ws/broadcast.js";
import { spendGuardAbi } from "../chain/abis/spendGuard.js";

/// Subscribes to every payment-lifecycle event SpendGuard emits, writes
/// each one to the `events` table via Prisma, keeps `agents.spentToday`
/// and `pending_requests` in sync, and pushes a live update over
/// WebSocket so the flow view doesn't need to poll.
export function watchPaymentEvents() {
  const address = config.SPEND_GUARD_ADDRESS as `0x${string}`;

  publicClient.watchContractEvent({
    address,
    abi: spendGuardAbi,
    eventName: "PaymentApproved",
    onLogs: async (logs) => {
      for (const log of logs) {
        try {
          const { requestId, agent, counterparty, amount } = log.args;
          const amt = amount ?? 0n;

          await prisma.event.create({
            data: { agent: agent!, counterparty: counterparty!, amount: amt, decision: "approved", txHash: log.transactionHash! },
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
        } catch (err) {
          console.error("Error processing PaymentApproved event:", err);
        }
      }
    },
  });

  publicClient.watchContractEvent({
    address,
    abi: spendGuardAbi,
    eventName: "PaymentBlocked",
    onLogs: async (logs) => {
      for (const log of logs) {
        try {
          const { agent, counterparty, amount, reason } = log.args;
          const amt = amount ?? 0n;

          await prisma.event.create({
            data: { agent: agent!, counterparty: counterparty!, amount: amt, decision: `blocked: ${reason}`, txHash: log.transactionHash! },
          });
          broadcast({ type: "payment_blocked", agent, counterparty, amount: amt.toString(), reason });
        } catch (err) {
          console.error("Error processing PaymentBlocked event:", err);
        }
      }
    },
  });

  publicClient.watchContractEvent({
    address,
    abi: spendGuardAbi,
    eventName: "PaymentEscalated",
    onLogs: async (logs) => {
      for (const log of logs) {
        try {
          const { requestId, agent, counterparty, amount } = log.args;
          const amt = amount ?? 0n;

          await prisma.event.create({
            data: { agent: agent!, counterparty: counterparty!, amount: amt, decision: "escalated", txHash: log.transactionHash! },
          });
          await prisma.pendingRequest.upsert({
            where: { requestId: requestId! },
            create: { requestId: requestId!, agent: agent!, counterparty: counterparty!, amount: amt, resolved: false },
            update: {},
          });
          broadcast({ type: "payment_escalated", requestId: requestId?.toString(), agent, counterparty, amount: amt.toString() });
        } catch (err) {
          console.error("Error processing PaymentEscalated event:", err);
        }
      }
    },
  });

  publicClient.watchContractEvent({
    address,
    abi: spendGuardAbi,
    eventName: "PendingApproved",
    onLogs: async (logs) => {
      for (const log of logs) {
        try {
          const { requestId, approver } = log.args;
          await prisma.pendingRequest.updateMany({ where: { requestId: requestId! }, data: { resolved: true } });
          broadcast({ type: "approval_resolved", requestId: requestId?.toString(), decision: "approved", approver });
        } catch (err) {
          console.error("Error processing PendingApproved event:", err);
        }
      }
    },
  });

  publicClient.watchContractEvent({
    address,
    abi: spendGuardAbi,
    eventName: "PendingRejected",
    onLogs: async (logs) => {
      for (const log of logs) {
        try {
          const { requestId, approver } = log.args;
          await prisma.pendingRequest.updateMany({ where: { requestId: requestId! }, data: { resolved: true } });
          broadcast({ type: "approval_resolved", requestId: requestId?.toString(), decision: "rejected", approver });
        } catch (err) {
          console.error("Error processing PendingRejected event:", err);
        }
      }
    },
  });
}