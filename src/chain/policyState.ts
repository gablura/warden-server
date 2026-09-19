import { prisma } from "../db/client.js";
import { policyRegistryAbi } from "./abis/policyRegistry.js";
import { ChainUnavailableError } from "./errors.js";
import type { Deployment } from "./orgContracts.js";
import { deploymentKey, resolveDeployment, resolveDeploymentForAgent } from "./orgContracts.js";

const SECONDS_PER_DAY = 86_400n;

// ── Policy snapshot cache ───────────────────────────────────────────
// When the chain read fails (e.g. RPC rate limit), return the last known
// good snapshot per agent instead of zeros. Cache TTL matches the
// indexer polling interval — data is at most ~1 minute stale.
const policyCache = new Map<string, AgentPolicySnapshot>();
const CACHE_TTL_MS = 60_000;
const cacheTimestamps = new Map<string, number>();

/// Evict a single agent's cached snapshot (e.g. after setPolicy confirms).
/// Call this with the agent's normalized address so subsequent reads hit
/// the chain immediately instead of waiting for TTL expiry.
export function evictPolicyCache(agentAddress: string): void {
  const key = agentAddress.toLowerCase();
  policyCache.delete(key);
  cacheTimestamps.delete(key);
}

// (doc comment preserved from the original — see git history for the long
// form: spentToday mirrors checkPolicy's lazy-reset rule, never raw storage.)
export type AgentPolicySnapshot = {
  exists: boolean;
  dailyCap: bigint;
  perTxCap: bigint;
  escalationThreshold: bigint;
  spentToday: bigint;
  /// Sum of this agent's live escalation reservations (PolicyRegistry.reserve),
  /// day-aware like spentToday: zero when the reservation day has rolled over.
  activeReserved: bigint;
  /// Newest reservation's raw expiry timestamp (block.timestamp + TTL at
  /// reserve time). Expiry is enforced lazily on-chain per day boundary; this
  /// is informational for dashboards, not an enforcement value.
  reservedUntil: bigint;
  /// Cap headroom left today AFTER spend AND live reservations — the value
  /// "can this agent still spend X right now" should be answered with.
  remainingToday: bigint;
  lastResetDay: bigint;
  currentDay: bigint;
  /// Block the snapshot was read at, so every value in it is from one consistent state.
  blockNumber: bigint;
  /// Which deployment served this snapshot (org id or null for global).
  deploymentOrgId: string | null;
};

/// Raw return of the `policies` auto-generated getter — struct fields in
/// declaration order, exactly as `PolicyRegistry.Policy` defines them
/// (the last two fields are the escalation-reservation pair, absent on
/// deployments that predate the reservation upgrade — see supportsReservations).
type RawPolicy = readonly (bigint | boolean)[];

/// Minimal ABI for the PRE-RESERVATION PolicyRegistry build: its `policies`
/// getter returns six fields (no activeReserved/reservedUntil). The compiled
/// artifact (and `policyRegistryAbi`) is always the newest source tree, but a
/// deployment can lag behind it — verified live against the ARC testnet
/// registry, whose `RESERVATION_TTL`/`globalReservedToday` revert and whose
/// `policies()` returns six words. Reading it with the eight-field ABI fails
/// to decode, so legacy deployments need this shape. Defined here rather than
/// in the generated ABI file because scripts/generate-abis.mjs overwrites
/// that file wholesale from the build artifact.
const legacyPolicyRegistryAbi = [
  {
    type: "function",
    name: "policies",
    inputs: [{ name: "", type: "address", internalType: "address" }],
    outputs: [
      { name: "dailyCap", type: "uint256", internalType: "uint256" },
      { name: "perTxCap", type: "uint256", internalType: "uint256" },
      { name: "escalationThreshold", type: "uint256", internalType: "uint256" },
      { name: "spentToday", type: "uint256", internalType: "uint256" },
      { name: "lastResetDay", type: "uint256", internalType: "uint256" },
      { name: "exists", type: "bool", internalType: "bool" },
    ],
    stateMutability: "view",
  },
] as const;

/// Does this deployment's registry include the escalation-reservation
/// upgrade? Probed once per deployment from `RESERVATION_TTL` (a constant the
/// old build does not define) and memoized: the answer is a property of the
/// deployed bytecode, never of the request, so re-probing per read would only
/// add latency and log noise. Truthy means the eight-field getter is safe;
/// falsy means reservations genuinely do not exist there, so `activeReserved`
/// is 0 by definition rather than "unread".
const reservationSupport = new Map<string, boolean>();

async function supportsReservations(deployment: Deployment): Promise<boolean> {
  const key = deploymentKey(deployment);
  const cached = reservationSupport.get(key);
  if (cached !== undefined) return cached;

  let supported: boolean;
  try {
    await deployment.publicClient.readContract({
      address: deployment.policyRegistry,
      abi: policyRegistryAbi,
      functionName: "RESERVATION_TTL",
    });
    supported = true;
  } catch {
    // Probe failure is either "legacy build" (revert: constant absent) or a
    // transient RPC problem. Treating both as legacy is the fail-safe
    // direction: the legacy read still returns caps and spend correctly, so
    // a false negative only under-reports reservations, while a false
    // positive would break every policy read outright.
    supported = false;
    console.warn(`[policyState] ${key}: RESERVATION_TTL probe failed — reading policies with the pre-reservation ABI`);
  }

  reservationSupport.set(key, supported);
  return supported;
}

/// Pick the getter that matches the deployed build, memoized above.
async function readRawPolicy(
  deployment: Deployment,
  agent: string,
  blockNumber: bigint,
): Promise<RawPolicy> {
  const withReservations = await supportsReservations(deployment);
  const policy = await deployment.publicClient.readContract({
    address: deployment.policyRegistry,
    abi: withReservations ? policyRegistryAbi : legacyPolicyRegistryAbi,
    functionName: "policies",
    args: [agent as `0x${string}`],
    blockNumber,
  });
  return policy as unknown as RawPolicy;
}

function toSnapshot(
  raw: RawPolicy,
  currentDay: bigint,
  blockNumber: bigint,
  deploymentOrgId: string | null,
): AgentPolicySnapshot {
  // Missing reservation fields mean a pre-reservation deployment: zero is the
  // truthful value there (no reservation exists to read), not a placeholder.
  const [
    dailyCap,
    perTxCap,
    escalationThreshold,
    rawSpentToday,
    lastResetDay,
    exists,
    rawActiveReserved = 0n,
    rawReservedUntil = 0n,
  ] = raw as readonly [bigint, bigint, bigint, bigint, bigint, boolean, bigint?, bigint?];

  // An address the registry has never seen is not an error: the getter answers
  // zeroes with `exists = false`. Callers surface that rather than inventing caps.
  if (!exists) {
    return {
      exists: false,
      dailyCap: 0n,
      perTxCap: 0n,
      escalationThreshold: 0n,
      spentToday: 0n,
      activeReserved: 0n,
      reservedUntil: 0n,
      remainingToday: 0n,
      lastResetDay: 0n,
      currentDay,
      blockNumber,
      deploymentOrgId,
    };
  }

  // Same lazy-reset rule as checkPolicy: spend and reservations only count
  // while their day is current.
  const counts = lastResetDay === currentDay;
  const spentToday = counts ? rawSpentToday : 0n;
  // Escalation reservations, day-aware like spentToday: a reservation stops
  // counting the moment its day rolls over (the registry's own checkPolicy
  // treats stored reservation values the same way at the day boundary).
  const activeReserved = counts ? rawActiveReserved : 0n;
  // Newest reservation's raw expiry timestamp; meaningless once the day has
  // rolled over (the reservation no longer counts), so it zeroes with them.
  const reservedUntil = counts ? rawReservedUntil : 0n;
  // committed = spend + live reservations, i.e. everything the cap is
  // already spoken for by. Mirrors the registry's own checkPolicy math.
  const committed = spentToday + activeReserved;

  return {
    exists: true,
    dailyCap,
    perTxCap,
    escalationThreshold,
    spentToday,
    activeReserved,
    reservedUntil,
    remainingToday: dailyCap > committed ? dailyCap - committed : 0n,
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
    const raw = await readRawPolicy(deployment, agent, block.number);
    return toSnapshot(raw, block.timestamp / SECONDS_PER_DAY, block.number, deployment.orgId);
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
  
  // Try chain read; on failure, fall back to cached snapshots.
  try {
    await Promise.all(
      [...groups.entries()].map(async ([orgId, indexes]) => {
        const deployment = await resolveDeployment(orgId);
        const block = await latestBlock(deployment);
        const currentDay = block.timestamp / SECONDS_PER_DAY;
        try {
          // One probe per deployment decides the getter shape for the whole
          // batch (see supportsReservations) — the multicall cannot mix ABIs.
          const policiesAbi = (await supportsReservations(deployment))
            ? policyRegistryAbi
            : legacyPolicyRegistryAbi;
          const results = await deployment.publicClient.multicall({
            contracts: indexes.map((i) => ({
              address: deployment.policyRegistry,
              abi: policiesAbi,
              functionName: "policies" as const,
              args: [normalized[i] as `0x${string}`],
            })),
            blockNumber: block.number,
            allowFailure: false,
          });
          indexes.forEach((inputIdx, batchIdx) => {
            const snap = toSnapshot(
              results[batchIdx] as RawPolicy,
              currentDay,
              block.number,
              deployment.orgId,
            );
            out[inputIdx] = snap;
            // Update cache on success
            policyCache.set(normalized[inputIdx], snap);
            cacheTimestamps.set(normalized[inputIdx], Date.now());
          });
        } catch (err) {
          throw new ChainUnavailableError("could not read agent policies from PolicyRegistry", { cause: err });
        }
      }),
    );
  } catch (err) {
    // Chain read failed — fill missing slots from cache
    for (let i = 0; i < normalized.length; i++) {
      if (!out[i]) {
        const cached = policyCache.get(normalized[i]);
        const ts = cacheTimestamps.get(normalized[i]) ?? 0;
        if (cached && Date.now() - ts < CACHE_TTL_MS) {
          out[i] = cached;
        } else {
          // No cache — return zeroed snapshot
          out[i] = {
            dailyCap: 0n, perTxCap: 0n, escalationThreshold: 0n,
            spentToday: 0n, activeReserved: 0n, exists: false,
            reservedUntil: 0n, remainingToday: 0n, lastResetDay: 0n,
            currentDay: 0n, blockNumber: 0n, deploymentOrgId: null,
          };
        }
      }
    }
    // Don't throw — let the route serve stale/cached data instead of 503
  }

  return out;
}

/// Read the pending policy change for an agent (if any).
/// Returns the scheduled change with effectiveAt, or null if none pending.
export type PendingPolicySnapshot = {
  dailyCap: bigint;
  perTxCap: bigint;
  escalationThreshold: bigint;
  effectiveAt: bigint; // Unix timestamp when the change becomes effective
} | null;

export async function readPendingPolicy(
  agent: string,
  deploymentOrOrgId?: Deployment | string | null,
): Promise<PendingPolicySnapshot> {
  const deployment = typeof deploymentOrOrgId === "object" && deploymentOrOrgId !== null
    ? deploymentOrOrgId
    : await resolveDeployment(deploymentOrOrgId ?? null);

  // The pendingPolicy getter exists on all builds that have the timelock feature
  // (same builds that have RESERVATION_TTL). Use the main ABI.
  try {
    const result = await deployment.publicClient.readContract({
      address: deployment.policyRegistry,
      abi: policyRegistryAbi,
      functionName: "pendingPolicy",
      args: [agent as `0x${string}`],
    }) as readonly [bigint, bigint, bigint, bigint];

    const [dailyCap, perTxCap, escalationThreshold, effectiveAt] = result;

    // effectiveAt = 0 means no pending change
    if (effectiveAt === 0n) return null;

    return { dailyCap, perTxCap, escalationThreshold, effectiveAt };
  } catch {
    // If the getter doesn't exist (older build), no pending changes possible
    return null;
  }
}
