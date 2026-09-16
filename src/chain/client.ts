import { createPublicClient, defineChain, http } from "viem";
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

export const publicClient = createPublicClient({ chain: arc, transport: http(config.ARC_RPC_URL) });

// Relayer identities (used for audit rows on the relayer signing path).
// Addresses are derived, never secret.
const adminAccount = privateKeyToAccount(config.ADMIN_PRIVATE_KEY as `0x${string}`);
const approverAccount = privateKeyToAccount(config.APPROVER_PRIVATE_KEY as `0x${string}`);
export const adminAddress = adminAccount.address;
export const approverAddress = approverAccount.address;
