import { prisma } from "../db/client.js";
import { broadcastEvent } from "../ws/broadcast.js";
import { startWatcher, type ProcessableLog } from "./runner.js";
import { policyRegistryAbi } from "../chain/abis/policyRegistry.js";
import { deploymentKey, listServedDeployments, type Deployment } from "../chain/orgContracts.js";

/// Keeps the `agents` and `allowlist` tables current whenever an admin
/// changes a policy on-chain, so the API never has to read the chain
/// directly to answer "what can this agent spend right now."
///
/// One watcher set per served deployment (global always; per-org mainnet
/// deployments in mainnet mode) — see watchPaymentEventsFor for the
/// deployment-scoping rationale.
///
/// Processing runs through indexer/runner.ts (idempotent, checkpointed,
/// backfilled on restart).
export async function watchPolicyEventsFor(deployment: Deployment): Promise<void> {
  const key = deploymentKey(deployment);
  const checkpointPrefix = key === "global" ? "" : `org:${key}:`;
  const watcherName = (event: string) => `${checkpointPrefix}policies:${event}`;

  const watchers = [
    {
      name: watcherName("PolicySet"),
      eventName: "PolicySet",
      onLog: async ({ args }: ProcessableLog) => {
        const { agent, dailyCap, perTxCap, escalationThreshold } = args as {
          agent?: string; dailyCap?: bigint; perTxCap?: bigint; escalationThreshold?: bigint;
        };

        await prisma.agent.upsert({
          where: { address: agent!.toLowerCase() },
          create: {
            address: agent!.toLowerCase(),
            dailyCap: dailyCap ?? 0n,
            perTxCap: perTxCap ?? 0n,
            escalationThreshold: escalationThreshold ?? 0n,
            spentToday: 0n,
            status: "active",
            // The registry this event came from IS the agent's deployment:
            // policies are per-deployment, so the row's org stamp is the
            // deployment's org (null for the global deployment). This stamp
            // is what tenant-scopes /agents and /audit — see routes/agents.ts.
            organizationId: deployment.orgId,
          },
          // Deliberately unstamped: an address PK is globally unique, so if
          // two deployments ever index the same address, update must not
          // silently reassign the row's org on every event.
          update: {
            dailyCap: dailyCap ?? 0n,
            perTxCap: perTxCap ?? 0n,
            escalationThreshold: escalationThreshold ?? 0n,
          },
        });

        broadcastEvent(
          {
            type: "policy_set",
            agent,
            dailyCap: dailyCap?.toString(),
            perTxCap: perTxCap?.toString(),
            escalationThreshold: escalationThreshold?.toString(),
          },
          deployment,
        );
      },
    },
    {
      name: watcherName("AllowlistUpdated"),
      eventName: "AllowlistUpdated",
      onLog: async ({ args }: ProcessableLog) => {
        const { agent, counterparty, allowed } = args as {
          agent?: string; counterparty?: string; allowed?: boolean;
        };

        await prisma.allowlist.upsert({
          where: { agent_counterparty: { agent: agent!.toLowerCase(), counterparty: counterparty!.toLowerCase() } },
          create: { agent: agent!.toLowerCase(), counterparty: counterparty!.toLowerCase(), allowed: allowed! },
          update: { allowed: allowed! },
        });

        broadcastEvent({ type: "allowlist_updated", agent, counterparty, allowed }, deployment);
      },
    },
  ];

  await Promise.all(
    watchers.map((w) =>
      startWatcher({
        name: w.name,
        address: deployment.policyRegistry,
        abi: policyRegistryAbi,
        eventName: w.eventName,
        client: deployment.publicClient,
        onLog: w.onLog,
      }),
    ),
  );
}

/// Index policy events for every served deployment (global always; per-org
/// mainnet deployments in mainnet mode).
export async function watchPolicyEvents(): Promise<void> {
  const deployments = await listServedDeployments();
  await Promise.all(deployments.map((deployment) => watchPolicyEventsFor(deployment)));
}
