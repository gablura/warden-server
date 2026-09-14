import { publicClient } from "./client.js";
import { config } from "../config.js";
import { policyRegistryAbi } from "./abis/policyRegistry.js";
import { ChainUnavailableError } from "./errors.js";

const SECONDS_PER_DAY = 86_400n;

/// A normalized `PolicyRegistry.policies(agent)` snapshot.
///
/// `spentToday` is deliberately *not* the raw storage value. On-chain it is a
/// lazily-reset counter: `recordSpend()` only zeroes it when a payment happens
/// on a new day, so between UTC midnight and that agent's first payment of the
/// day the stored number still belongs to yesterday. `checkPolicy()` compares
/// `lastResetDay` against today before using it, and this mirrors that rule —
/// otherwise the API would report yesterday's spend against today's cap and
/// understate the agent's remaining budget.
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
};

/// Raw return of the `policies` auto-generated getter — struct fields in
/// declaration order, exactly as `PolicyRegistry.Policy` defines them.
type RawPolicy = readonly [bigint, bigint, bigint, bigint, bigint, boolean];

function toSnapshot(raw: RawPolicy, currentDay: bigint, blockNumber: bigint): AgentPolicySnapshot {
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
  };
}

/// One `eth_getBlockByNumber` gives us both the block to pin the state read to
/// and the timestamp that decides which UTC day the snapshot belongs to.
async function latestBlock() {
  try {
    return await publicClient.getBlock({ blockTag: "latest" });
  } catch (err) {
    throw new ChainUnavailableError("could not read the latest Arc block", { cause: err });
  }
}

const registryAddress = () => config.POLICY_REGISTRY_ADDRESS as `0x${string}`;

/// Live policy for a single agent, read straight from PolicyRegistry.
/// Throws ChainUnavailableError rather than returning a partial answer.
export async function readAgentPolicy(agent: string): Promise<AgentPolicySnapshot> {
  const block = await latestBlock();

  try {
    const raw = await publicClient.readContract({
      address: registryAddress(),
      abi: policyRegistryAbi,
      functionName: "policies",
      args: [agent as `0x${string}`],
      blockNumber: block.number,
    });

    return toSnapshot(raw as RawPolicy, block.timestamp / SECONDS_PER_DAY, block.number);
  } catch (err) {
    throw new ChainUnavailableError(`could not read the on-chain policy for ${agent}`, { cause: err });
  }
}

/// Live policy for many agents in a single RPC round-trip.
///
/// Batched through Multicall3 (deployed on Arc at the canonical address) so a
/// dashboard listing every agent costs one `eth_call` instead of one per row.
/// Results are returned in the same order as `agents` — never as a sparse map,
/// so a caller cannot silently end up pairing an agent with another's caps.
///
/// `allowFailure: false` is intentional: individual calls cannot legitimately
/// revert (the getter answers zeroes for unknown addresses), so a failure here
/// means the registry address, ABI, or RPC is wrong and must not be papered over.
export async function readAgentPolicies(agents: readonly string[]): Promise<AgentPolicySnapshot[]> {
  if (agents.length === 0) return [];

  const block = await latestBlock();
  const currentDay = block.timestamp / SECONDS_PER_DAY;
  const address = registryAddress();

  try {
    const results = await publicClient.multicall({
      contracts: agents.map((agent) => ({
        address,
        abi: policyRegistryAbi,
        functionName: "policies" as const,
        args: [agent as `0x${string}`],
      })),
      blockNumber: block.number,
      allowFailure: false,
    });

    return results.map((raw) => toSnapshot(raw as RawPolicy, currentDay, block.number));
  } catch (err) {
    throw new ChainUnavailableError("could not read agent policies from PolicyRegistry", { cause: err });
  }
}
