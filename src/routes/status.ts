import type { FastifyInstance } from "fastify";
import { prisma, serializeBigInts } from "../db/client.js";
import { publicClient } from "../chain/client.js";
import { readAgentPolicies } from "../chain/policyState.js";

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

    // Agents approaching their daily cap — the hardening review specifically
    // calls out "agents approaching their daily cap" as something a human
    // should be notified about. We flag agents at >80% of their daily cap
    // using the live policy read (same path as /agents).
    const policies = await readAgentPolicies(agents.map((a) => a.address));
    const agentHealth = agents.map((agent, i) => {
      const policy = policies[i]!;
      const spentPct = policy.dailyCap > 0n ? Number((policy.spentToday * 100n) / policy.dailyCap) : 0;
      return {
        address: agent.address,
        label: agent.label,
        status: agent.status,
        spentToday: policy.spentToday,
        dailyCap: policy.dailyCap,
        spentPct,
        nearCap: spentPct >= 80,
      };
    });

    const nearCapAgents = agentHealth.filter((a) => a.nearCap);

    return serializeBigInts({
      ok: true,
      chainHead,
      indexers: indexerLag,
      agents: {
        total: agents.length,
        nearCap: nearCapAgents.length,
        nearCapList: nearCapAgents,
      },
    });
  });
}
