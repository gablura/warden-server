import type { FastifyInstance } from "fastify";
import { prisma, serializeBigInts } from "../db/client.js";
import { publicClient } from "../chain/client.js";
import { readAgentPolicies } from "../chain/policyState.js";
import { deploymentKey, resolveDeployment } from "../chain/orgContracts.js";

/// Monitoring endpoint (hardening review §5.2). Surfaces indexer lag, agent
/// health, and system status so a human (or alerting tool) can spot problems
/// without grepping logs. Kept lightweight — computed on demand, no background
/// polling or persistent metrics store. The /health endpoint (in server.ts)
/// stays simple for load balancer probes; this one is for operators.
export async function statusRoutes(app: FastifyInstance) {
  app.get("/status", async () => {
    const [checkpoints, agents, chainHead] = await Promise.all([
      prisma.indexerCheckpoint.findMany(),
      prisma.agent.findMany(),
      publicClient.getBlockNumber(),
    ]);

    const checkpointByWatcher = new Map(checkpoints.map((c) => [c.watcher, c]));

    // Compute lag for each indexer: how many blocks behind the chain head.
    // A healthy indexer stays within a few blocks; a lag of >100 usually
    // means the RPC is rate-limiting or the watcher has stalled.
    const indexerLag = [
      { name: "payments", checkpoint: checkpointByWatcher.get("payments:PaymentApproved") },
      { name: "policies", checkpoint: checkpointByWatcher.get("policies:PolicySet") },
    ].map(({ name, checkpoint }) => ({
      name,
      lastBlock: checkpoint?.lastBlock ?? null,
      lag: checkpoint ? Number(chainHead - checkpoint.lastBlock) : null,
    }));

    // Per-deployment indexers (per-org mainnet deployments). Their watcher
    // names carry an `org:<deploymentKey>:` prefix and their chain head comes
    // from that org's own RPC, so lag is computed per chain. Additive: the
    // global entries above stay stable for existing dashboards/alerts.
    const orgIndexerLag = await Promise.all(
      checkpoints
        .filter((c) => c.watcher.startsWith("org:"))
        .map(async (c) => {
          const deploymentId = c.watcher.split(":")[1]!;
          let lag: number | null = null;
          try {
            const deployment = await resolveDeployment(deploymentId);
            // The org may have been un-deployed since indexing started —
            // resolveDeployment then returns the global deployment, which
            // would measure lag against the wrong chain. Report the raw
            // checkpoint with no lag in that case.
            if (deploymentKey(deployment) === deploymentId) {
              const head = await deployment.publicClient.getBlockNumber();
              lag = Number(head - c.lastBlock);
            }
          } catch {
            // Unreachable org RPC — the checkpoint row is still worth surfacing.
          }
          return { name: c.watcher, deployment: deploymentId, lastBlock: c.lastBlock, lag };
        }),
    );

    // Agents approaching their daily cap — the hardening review specifically
    // calls out "agents approaching their daily cap" as something a human
    // should be notified about. We flag agents at >80% of their daily cap
    // using the live policy read (same path as /agents).
    const policies = await readAgentPolicies(agents.map((a) => a.address));
    const agentHealth = agents.map((agent, i) => {
      const policy = policies[i]!;
      // Same committed-headroom rule as /agents: spend + live reservations.
      const committed = policy.spentToday + policy.activeReserved;
      const spentPct = policy.dailyCap > 0n ? Number((committed * 100n) / policy.dailyCap) : 0;
      return {
        address: agent.address,
        label: agent.label,
        status: agent.status,
        spentToday: policy.spentToday,
        activeReserved: policy.activeReserved,
        dailyCap: policy.dailyCap,
        spentPct,
        nearCap: spentPct >= 80,
      };
    });

    const nearCapAgents = agentHealth.filter((a) => a.nearCap);

    return serializeBigInts({
      ok: true,
      chainHead,
      indexers: [...indexerLag, ...orgIndexerLag],
      agents: {
        total: agents.length,
        nearCap: nearCapAgents.length,
        nearCapList: nearCapAgents,
      },
    });
  });
}
