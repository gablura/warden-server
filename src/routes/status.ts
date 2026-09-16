import type { FastifyInstance } from "fastify";
import { prisma, serializeBigInts } from "../db/client.js";
import { readAgentPolicies } from "../chain/policyState.js";
import { deploymentKey, resolveDeployment } from "../chain/orgContracts.js";
import { optionalAuth } from "../auth/clerkAuth.js";
import { paymentCheckpointName } from "../indexer/watchPaymentEvents.js";
import { policyCheckpointName } from "../indexer/watchPolicyEvents.js";

/// Monitoring endpoint (hardening review §5.2). Surfaces indexer lag, agent
/// health, and system status so a human (or alerting tool) can spot problems
/// without grepping logs. Kept lightweight — computed on demand, no background
/// polling or persistent metrics store. The /health endpoint (in server.ts)
/// stays simple for load balancer probes; this one is for operators.
///
/// Scope follows the rule every other read route uses (/approvals, /agents,
/// /audit): credentials are verified when presented (a bad key is a 401,
/// never a silent downgrade to anonymous), the caller's resolved deployment
/// decides what they see — an org member sees their own deployment's agents
/// and indexer lag, while service credentials and anonymous callers see the
/// global deployment. On mainnet an org's indexer checkpoints and near-cap
/// agents would otherwise leak across tenants, so this endpoint is scoped
/// exactly like the data routes it summarizes.
export async function statusRoutes(app: FastifyInstance) {
  app.get("/status", { preHandler: optionalAuth() }, async (req) => {
    // The caller's deployment is the lens for everything below: its agents,
    // its watchers' checkpoints, and its own chain for lag measurement (the
    // same discipline /approvals uses — lag must be measured against the
    // chain the watcher feeds from, or the number is meaningless).
    const deployment = await resolveDeployment(req.operator?.orgId);
    const key = deploymentKey(deployment);

    const [checkpoints, agents, chainHead] = await Promise.all([
      prisma.indexerCheckpoint.findMany(),
      prisma.agent.findMany({
        // Agents are org-stamped by the indexers (see watchPaymentEvents /
        // watchPolicyEvents); `organizationId: null` matches the unstamped
        // global-deployment agents — the same filter /agents applies.
        where: deployment.orgId === null ? { organizationId: null } : { organizationId: deployment.orgId },
      }),
      deployment.publicClient.getBlockNumber().catch(() => 0n),
    ]);

    const checkpointByWatcher = new Map(checkpoints.map((c) => [c.watcher, c]));

    // Compute lag for this deployment's indexers: how many blocks behind
    // their chain head. A healthy indexer stays within a few blocks; a lag
    // of >100 usually means the RPC is rate-limiting or the watcher stalled.
    // Checkpoint names come from the same helpers the indexers use, so a
    // rename can never split the writer from this reader.
    const indexerLag = [
      { name: "payments", checkpoint: checkpointByWatcher.get(paymentCheckpointName(key, "PaymentApproved")) },
      { name: "policies", checkpoint: checkpointByWatcher.get(policyCheckpointName(key, "PolicySet")) },
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
      indexers: indexerLag,
      agents: {
        total: agents.length,
        nearCap: nearCapAgents.length,
        nearCapList: nearCapAgents,
      },
    });
  });
}
