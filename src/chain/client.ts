import { createPublicClient, createWalletClient, defineChain, http, getContract } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { config } from "../config.js";

// Replace with Arc's published chain definition once you have it —
// this is a placeholder shape. USDC as native gas is the detail worth
// double-checking against Arc's actual docs before you deploy.
export const arc = defineChain({
  id: config.ARC_CHAIN_ID,
  name: "Arc",
  nativeCurrency: { name: "USDC", symbol: "USDC", decimals: 6 },
  rpcUrls: { default: { http: [config.ARC_RPC_URL] } },
});

export const publicClient = createPublicClient({ chain: arc, transport: http(config.ARC_RPC_URL) });

const adminAccount = privateKeyToAccount(config.ADMIN_PRIVATE_KEY as `0x${string}`);
const approverAccount = privateKeyToAccount(config.APPROVER_PRIVATE_KEY as `0x${string}`);

export const adminWalletClient = createWalletClient({ account: adminAccount, chain: arc, transport: http(config.ARC_RPC_URL) });
export const approverWalletClient = createWalletClient({ account: approverAccount, chain: arc, transport: http(config.ARC_RPC_URL) });

// Trimmed ABI fragments for just the functions the API calls. Swap these
// for the real compiled ABIs (packages/contract-abis) once contracts are built.
const policyRegistryAbi = [
  {
    type: "function", name: "setPolicy", stateMutability: "nonpayable",
    inputs: [
      { name: "agent", type: "address" }, { name: "dailyCap", type: "uint256" },
      { name: "perTxCap", type: "uint256" }, { name: "escalationThreshold", type: "uint256" },
    ], outputs: [],
  },
  {
    type: "function", name: "setAllowlist", stateMutability: "nonpayable",
    inputs: [{ name: "agent", type: "address" }, { name: "counterparty", type: "address" }, { name: "allowed", type: "bool" }],
    outputs: [],
  },
  {
    type: "function", name: "policies", stateMutability: "view",
    inputs: [{ name: "agent", type: "address" }],
    outputs: [
      { name: "dailyCap", type: "uint256" }, { name: "perTxCap", type: "uint256" },
      { name: "escalationThreshold", type: "uint256" }, { name: "spentToday", type: "uint256" },
      { name: "lastResetDay", type: "uint256" }, { name: "exists", type: "bool" },
    ],
  },
] as const;

const spendGuardAbi = [
  { type: "function", name: "approvePending", stateMutability: "nonpayable", inputs: [{ name: "requestId", type: "uint256" }], outputs: [] },
  { type: "function", name: "rejectPending", stateMutability: "nonpayable", inputs: [{ name: "requestId", type: "uint256" }], outputs: [] },
] as const;

export const policyRegistry = {
  read: getContract({ address: config.POLICY_REGISTRY_ADDRESS as `0x${string}`, abi: policyRegistryAbi, client: publicClient }),
  admin: getContract({ address: config.POLICY_REGISTRY_ADDRESS as `0x${string}`, abi: policyRegistryAbi, client: adminWalletClient }),
};

export const spendGuard = {
  approver: getContract({ address: config.SPEND_GUARD_ADDRESS as `0x${string}`, abi: spendGuardAbi, client: approverWalletClient }),
};