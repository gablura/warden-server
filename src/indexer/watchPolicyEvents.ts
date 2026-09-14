import { publicClient } from "../chain/client.js";
import { config } from "../config.js";
import { prisma } from "../db/client.js";
import { broadcast } from "../ws/broadcast.js";
import { policyRegistryAbi } from "../chain/abis/policyRegistry.js";

/// Keeps the `agents` and `allowlist` tables current whenever an admin
/// changes a policy on-chain, so the API never has to read the chain
/// directly to answer "what can this agent spend right now."
export function watchPolicyEvents() {
  const address = config.POLICY_REGISTRY_ADDRESS as `0x${string}`;

  publicClient.watchContractEvent({
    address,
    abi: policyRegistryAbi,
    eventName: "PolicySet",
    onLogs: async (logs) => {
      for (const log of logs) {
        try {
          const { agent, dailyCap, perTxCap, escalationThreshold } = log.args;

          await prisma.agent.upsert({
            where: { address: agent! },
            create: {
              address: agent!,
              dailyCap: dailyCap ?? 0n,
              perTxCap: perTxCap ?? 0n,
              escalationThreshold: escalationThreshold ?? 0n,
              spentToday: 0n,
              status: "active",
            },
            update: {
              dailyCap: dailyCap ?? 0n,
              perTxCap: perTxCap ?? 0n,
              escalationThreshold: escalationThreshold ?? 0n,
            },
          });

          broadcast({
            type: "policy_set",
            agent,
            dailyCap: dailyCap?.toString(),
            perTxCap: perTxCap?.toString(),
            escalationThreshold: escalationThreshold?.toString(),
          });
        } catch (err) {
          console.error("Error processing PolicySet event:", err);
        }
      }
    },
  });

  publicClient.watchContractEvent({
    address,
    abi: policyRegistryAbi,
    eventName: "AllowlistUpdated",
    onLogs: async (logs) => {
      for (const log of logs) {
        try {
          const { agent, counterparty, allowed } = log.args;

          await prisma.allowlist.upsert({
            where: { agent_counterparty: { agent: agent!, counterparty: counterparty! } },
            create: { agent: agent!, counterparty: counterparty!, allowed: allowed! },
            update: { allowed: allowed! },
          });

          broadcast({ type: "allowlist_updated", agent, counterparty, allowed });
        } catch (err) {
          console.error("Error processing AllowlistUpdated event:", err);
        }
      }
    },
  });
}