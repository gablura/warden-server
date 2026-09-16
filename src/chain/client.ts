import { createPublicClient, defineChain, fallback, http, type Transport } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { config } from "../config.js";

// Global (env) deployment surface. Per-org deployments live in
// chain/orgContracts.ts; per-call contract bindings are built in
// chain/signing.ts and chain/policyState.ts. This module keeps only what
// is inherently global: the chain definition, the shared read client
// (indexer, queue view, status), and the relayer identities for audit rows.

// Replace with Arc's published chain definition once you have it —
// this is a placeholder shape. USDC as native gas is the detail worth
// double-checking against Arc's actual docs before you deploy.
export const arc = defineChain({
  id: config.ARC_CHAIN_ID,
  name: "Arc",
  nativeCurrency: { name: "USDC", symbol: "USDC", decimals: 6 },
  rpcUrls: { default: { http: [config.ARC_RPC_URL] } },
  contracts: {
    // Multicall3, deployed on Arc at the canonical address — lets the policy
    // reads in chain/policyState.ts batch every agent into one eth_call.
    // Declaring it here is what makes viem's multicall() usable on a chain
    // that isn't a viem built-in.
    multicall3: { address: "0xca11bde05977b3631167028862be2a173976ca11" },
  },
});

/// Per-request cap for each endpoint in a fallback chain. Without it, an
/// endpoint that silently DROPS packets (firewall behavior, not connection
/// refusal) hangs the connect for minutes and stalls the whole chain —
/// the fallback only helps if a sick endpoint yields promptly. Generous
/// enough for getLogs over long ranges; far below the minutes a dropped
/// connect would otherwise wait.
const RPC_TIMEOUT_MS = 10_000;

/// Shared transport construction. Every client — the global read client
/// here and the per-deployment read/write clients in orgContracts.ts —
/// goes through this so backup-RPC failover (hardening review §5.5,
/// incident scenario 3) is automatic everywhere instead of a manual
/// ARC_RPC_URL swap.
///
/// Shape: the primary URL first, then ARC_RPC_FALLBACK_URLS in order.
/// fallback() ranks endpoints by observed health — a primary that flakes
/// demotes itself and a backup carries traffic until it recovers — and
/// retryCount re-issues a failed request against the next endpoint within
/// the same call, so one RPC blip no longer surfaces as a 503 or a lost
/// watcher poll.
export function arcTransport(rpcUrl: string): Transport {
  const urls = [rpcUrl, ...(config.ARC_RPC_FALLBACK_URLS ?? [])].filter(
    (u, i, all) => all.indexOf(u) === i,
  );
  if (urls.length === 1) return http(urls[0]!, { timeout: RPC_TIMEOUT_MS });
  // Inside a chain, per-endpoint retries stay at 0: rotating to the next
  // endpoint IS the retry, and re-trying a dead primary 3× (each burning
  // the full timeout) is exactly the multi-second stall the chain exists
  // to prevent. The single-endpoint path keeps viem's default retries —
  // with no backup, in-place retries are the only resilience there is.
  return fallback(
    urls.map((u) => http(u, { retryCount: 0, timeout: RPC_TIMEOUT_MS })),
    { rank: true },
  );
}

export const publicClient = createPublicClient({ chain: arc, transport: arcTransport(config.ARC_RPC_URL) });

// Relayer identities (used for audit rows on the relayer signing path).
// Addresses are derived, never secret.
const adminAccount = privateKeyToAccount(config.ADMIN_PRIVATE_KEY as `0x${string}`);
const approverAccount = privateKeyToAccount(config.APPROVER_PRIVATE_KEY as `0x${string}`);
export const adminAddress = adminAccount.address;
export const approverAddress = approverAccount.address;
