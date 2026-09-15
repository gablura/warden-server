import { config } from "../config.js";
import { prisma } from "../db/client.js";
import { broadcast } from "../ws/broadcast.js";
import { startWatcher, type ProcessableLog } from "./runner.js";
import { policyRegistryAbi } from "../chain/abis/policyRegistry.js";

/// Keeps the `agents` and `allowlist` tables current whenever an admin
/// changes a policy on-chain, so the API never has to read the chain
/// directly to answer "what can this agent spend right now."
/// Processing runs through indexer/runner.ts (idempotent, checkpointed,
/// backfilled on restart).
export async function watchPolicyEvents(): Promise<void> {
  const address = config.POLICY_REGISTRY_ADDRESS as `0x${string}`;

  const watchers = [
    {
      name: "policies:PolicySet",
      eventName: "PolicySet",
      onLog: async ({ args }: ProcessableLog) => {
        const { agent, dailyCap, perTxCap, escalationThreshold } = args as {
          agent?: string; dailyCap?: bigint; perTxCap?: bigint; escalationThreshold?: bigint;
        };

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
      },
    },
    {
      name: "policies:AllowlistUpdated",
      eventName: "AllowlistUpdated",
      onLog: async ({ args }: ProcessableLog) => {
        const { agent, counterparty, allowed } = args as {
          agent?: string; counterparty?: string; allowed?: boolean;
        };

        await prisma.allowlist.upsert({
          where: { agent_counterparty: { agent: agent!, counterparty: counterparty! } },
          create: { agent: agent!, counterparty: counterparty!, allowed: allowed! },
          update: { allowed: allowed! },
        });

        broadcast({ type: "allowlist_updated", agent, counterparty, allowed });
      },
    },
  ];

  await Promise.all(
    watchers.map((w) =>
      startWatcher({ name: w.name, address, abi: policyRegistryAbi, eventName: w.eventName, onLog: w.onLog }),
    ),
  );
}