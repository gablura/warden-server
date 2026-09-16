import { prisma } from "../db/client.js";
import { policyRegistryAbi } from "./abis/policyRegistry.js";
import { ChainUnavailableError } from "./errors.js";
import type { Deployment } from "./orgContracts.js";
import { resolveDeployment, resolveDeploymentForAgent } from "./orgContracts.js";

const SECONDS_PER_DAY = 86_400n;

// (doc comment preserved from the original — see git history for the long
// form: spentToday mirrors checkPolicy's lazy-reset rule, never raw storage.)
export type AgentPolicySnapshot = {
  exists: boolean;
  dailyCap: bigint;
  perTxCap: bigint;
  escalationThreshold: bigint;
  spentToday: bigint;
  remainingToday: bigint;
  lastResetDay: bigint;
  currentDay: bigint;
  /// Block the snapshot was read at, so every value in it is from one consistent state.
  blockNumber: bigint;
  /// Which deployment served this snapshot (org id or null for global).
  deploymentOrgId: string | null;
};

/// Raw return of the `policies` auto-generated getter — struct fields in
/// declaration order, exactly as `PolicyRegistry.Policy` defines them.
type RawPolicy = readonly [bigint, bigint, bigint, bigint, bigint, boolean];

function toSnapshot(
  raw: RawPolicy,
  currentDay: bigint,
  blockNumber: bigint,
  deploymentOrgId: string | null,
): AgentPolicySnapshot {
  const [dailyCap, perTxCap, escalationThreshold, rawSpentToday, lastResetDay, exists] = raw;

  // An address the registry has never seen is not an error: the getter returns
  // zeroes with `exists = false`. Callers surface that rather than inventing caps.
  if (!exists) {
    return {
      exists: false,
      dailyCap: 0n,
      perTxCap: 0n,
      escalationThreshold: 0n,
      spentToday: 0n,
      remainingToday: 0n,
      lastResetDay: 0n,
      currentDay,
      blockNumber,
      deploymentOrgId,
    };
  }

  const spentToday = lastResetDay === currentDay ? rawSpentToday : 0n;

  return {
    exists: true,
    dailyCap,
    perTxCap,
    escalationThreshold,
    spentToday,
    remainingToday: dailyCap > spentToday ? dailyCap - spentToday : 0n,
    lastResetDay,
    currentDay,
    blockNumber,
    deploymentOrgId,
  };
}

/// One `eth_getBlockByNumber` gives us both the block to pin the state read to
/// and the timestamp that decides which UTC day the snapshot belongs to.
async function latestBlock(deployment: Deployment) {
  try {
    return await deployment.publicClient.getBlock({ blockTag: "latest" });
  } catch (err) {
    throw new ChainUnavailableError("could not read the latest block", { cause: err });
  }
}

/// Live policy for a single agent, read straight from the deployment that
/// owns it (the agent's org deployment, or global). Throws
/// ChainUnavailableError rather than returning a partial answer.
export async function readAgentPolicy(agent: string, orgId?: string | null): Promise<AgentPolicySnapshot> {
  const deployment = orgId === undefined ? await resolveDeploymentForAgent(agent) : await resolveDeployment(orgId);
  const block = await latestBlock(deployment);

  try {
    const raw = await deployment.publicClient.readContract({
      address: deployment.policyRegistry,
      abi: policyRegistryAbi,
      functionName: "policies",
      args: [agent as `0x${string}`],
      blockNumber: block.number,
    });

    return toSnapshot(raw as RawPolicy, block.timestamp / SECONDS_PER_DAY, block.number, deployment.orgId);
  } catch (err) {
    throw new ChainUnavailableError(`could not read the on-chain policy for ${agent}`, { cause: err });
  }
}

/// Live policy for many agents, grouped by owning deployment so each
/// multicall batch hits the right chain. Results return in input order —
/// never as a sparse map, so a caller cannot silently pair an agent with
/// another's caps.
///
/// `allowFailure: false` is intentional: individual calls cannot legitimately
/// revert (the getter answers zeroes for unknown addresses), so a failure here
/// means the registry address, ABI, or RPC is wrong and must not be papered over.
export async function readAgentPolicies(agents: readonly string[]): Promise<AgentPolicySnapshot[]> {
  if (agents.length === 0) return [];

  const normalized = agents.map((a) => a.toLowerCase());
  const rows = await prisma.agent.findMany({
    where: { address: { in: normalized } },
    select: { address: true, organizationId: true },
  });
  const orgByAgent = new Map(rows.map((r) => [r.address.toLowerCase(), r.organizationId]));

  // Group input indexes by org so each deployment gets exactly one batch.
  const groups = new Map<string | null, number[]>();
  normalized.forEach((addr, i) => {
    const orgId = orgByAgent.get(addr) ?? null;
    if (!groups.has(orgId)) groups.set(orgId, []);
    groups.get(orgId)!.push(i);
  });

  const out: AgentPolicySnapshot[] = new Array(agents.length);
  await Promise.all(
    [...groups.entries()].map(async ([orgId, indexes]) => {
      const deployment = await resolveDeployment(orgId);
      const block = await latestBlock(deployment);
      const currentDay = block.timestamp / SECONDS_PER_DAY;
      try {
        const results = await deployment.publicClient.multicall({
          contracts: indexes.map((i) => ({
            address: deployment.policyRegistry,
            abi: policyRegistryAbi,
            functionName: "policies" as const,
            args: [normalized[i] as `0x${string}`],
          })),
          blockNumber: block.number,
          allowFailure: false,
        });
        indexes.forEach((inputIdx, batchIdx) => {
          out[inputIdx] = toSnapshot(
            results[batchIdx] as RawPolicy,
            currentDay,
            block.number,
            deployment.orgId,
          );
        });
      } catch (err) {
        throw new ChainUnavailableError("could not read agent policies from PolicyRegistry", { cause: err });
      }
    }),
  );

  return out;
}
