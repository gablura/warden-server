import { createPublicClient, createWalletClient, defineChain, http, getContract } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { config } from "../config.js";
import { policyRegistryAbi } from "./abis/policyRegistry.js";
import { spendGuardAbi } from "./abis/spendGuard.js";

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

const adminAccount = privateKeyToAccount(config.ADMIN_PRIVATE_KEY as `0x${string}`);
const approverAccount = privateKeyToAccount(config.APPROVER_PRIVATE_KEY as `0x${string}`);

export const adminWalletClient = createWalletClient({ account: adminAccount, chain: arc, transport: http(config.ARC_RPC_URL) });
export const approverWalletClient = createWalletClient({ account: approverAccount, chain: arc, transport: http(config.ARC_RPC_URL) });

// ABIs are generated from the compiled Foundry artifacts — see
// scripts/generate-abis.mjs and run `npm run abis:generate` after any
// contract change. Imported rather than hand-trimmed so a signature
// drift is a type error here instead of a bad calldata at runtime.
export const policyRegistry = {
  read: getContract({ address: config.POLICY_REGISTRY_ADDRESS as `0x${string}`, abi: policyRegistryAbi, client: publicClient }),
  admin: getContract({ address: config.POLICY_REGISTRY_ADDRESS as `0x${string}`, abi: policyRegistryAbi, client: adminWalletClient }),
};

export const spendGuard = {
  read: getContract({ address: config.SPEND_GUARD_ADDRESS as `0x${string}`, abi: spendGuardAbi, client: publicClient }),
  approver: getContract({ address: config.SPEND_GUARD_ADDRESS as `0x${string}`, abi: spendGuardAbi, client: approverWalletClient }),
};