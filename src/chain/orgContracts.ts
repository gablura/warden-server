import { createPublicClient, createWalletClient, defineChain, http } from "viem";
import type { Account, Chain, PublicClient, Transport, WalletClient } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { isAddress } from "viem";
import { config } from "../config.js";
import { prisma } from "../db/client.js";

// ── Per-org contract addressing (§7) ─────────────────────────────────
//
// Every verified org may own a full deployment (3 contracts + RPC + chain
// id). Resolution rules, in order:
//
//   1. No org context (service callers, unknown agents) → global env
//      deployment. This is the server's connected deployment.
//   2. Testnet mode → global deployment, always. Org mainnet fields are
//      inert until mainnet — testnet stays one shared playground.
//   3. Mainnet mode + org with all five mainnet* fields set and valid →
//      the org's own deployment (dedicated viem clients, cached).
//   4. Mainnet mode + org with a PARTIAL set → OrgDeploymentError. A half-
//      configured deployment must fail loudly, never silently route to the
//      global contracts (that would land a mainnet-intended write on the
//      wrong chain).
//   5. Otherwise (unverified, or verified without its own deployment) →
//      global deployment. Write authorization for unverified orgs is the
//      production gate's job, not this resolver's.
//
// Assumption: the org chain exposes Multicall3 at the canonical address
// (true for every major EVM chain). Reads batch through it exactly like
// the global path; a chain without it surfaces ChainUnavailableError.

export class OrgDeploymentError extends Error {
  readonly statusCode = 500;
  readonly code = "org_deployment_misconfigured";
  constructor(message: string) {
    super(message);
    this.name = "OrgDeploymentError";
  }
}

export interface ChainClients {
  publicClient: PublicClient<Transport, Chain>;
  adminWalletClient: WalletClient<Transport, Chain, Account>;
  approverWalletClient: WalletClient<Transport, Chain, Account>;
}

export interface Deployment extends ChainClients {
  /// Null for the global env deployment, org id otherwise.
  orgId: string | null;
  chainId: number;
  rpcUrl: string;
  policyRegistry: `0x${string}`;
  spendGuard: `0x${string}`;
  auditLog: `0x${string}`;
}

const clientCache = new Map<string, ChainClients>();

function chainClients(rpcUrl: string, chainId: number): ChainClients {
  const key = `${rpcUrl}|${chainId}`;
  const cached = clientCache.get(key);
  if (cached) return cached;

  const chain = defineChain({
    id: chainId,
    name: `warden-${chainId}`,
    nativeCurrency: { name: "USDC", symbol: "USDC", decimals: 6 },
    rpcUrls: { default: { http: [rpcUrl] } },
    contracts: {
      multicall3: { address: "0xca11bde05977b3631167028862be2a173976ca11" },
    },
  });

  const transport = http(rpcUrl);
  // The same server-held keys operate every deployment: each org's contracts
  // are deployed with ADMIN_PRIVATE_KEY as admin (see contracts/script).
  const adminAccount = privateKeyToAccount(config.ADMIN_PRIVATE_KEY as `0x${string}`);
  const approverAccount = privateKeyToAccount(config.APPROVER_PRIVATE_KEY as `0x${string}`);

  const clients: ChainClients = {
    publicClient: createPublicClient({ chain, transport }),
    adminWalletClient: createWalletClient({ account: adminAccount, chain, transport }),
    approverWalletClient: createWalletClient({ account: approverAccount, chain, transport }),
  };
  clientCache.set(key, clients);
  return clients;
}

function globalDeployment(): Deployment {
  return {
    orgId: null,
    chainId: config.ARC_CHAIN_ID,
    rpcUrl: config.ARC_RPC_URL,
    policyRegistry: config.POLICY_REGISTRY_ADDRESS as `0x${string}`,
    spendGuard: config.SPEND_GUARD_ADDRESS as `0x${string}`,
    auditLog: config.AUDIT_LOG_ADDRESS as `0x${string}`,
    ...chainClients(config.ARC_RPC_URL, config.ARC_CHAIN_ID),
  };
}

/// Resolve the deployment serving an org. Never returns a partial config.
export async function resolveDeployment(orgId: string | null | undefined): Promise<Deployment> {
  if (!orgId) return globalDeployment();
  if (config.WARDEN_NETWORK !== "mainnet") return globalDeployment();

  const org = await prisma.organization.findUnique({ where: { id: orgId } });
  if (!org) return globalDeployment();

  const fields = [
    org.mainnetPolicyRegistry,
    org.mainnetSpendGuard,
    org.mainnetAuditLog,
    org.mainnetRpcUrl,
    org.mainnetChainId,
  ];
  const set = fields.filter((f) => f !== null && f !== undefined && f !== "");
  if (set.length === 0) return globalDeployment();
  if (set.length !== 5) {
    throw new OrgDeploymentError(
      `organization ${org.id} has a partial mainnet deployment (only ${set.length}/5 fields set) — complete or clear it`,
    );
  }

  const [policyRegistry, spendGuard, auditLog] = [org.mainnetPolicyRegistry!, org.mainnetSpendGuard!, org.mainnetAuditLog!];
  for (const [name, addr] of [["mainnetPolicyRegistry", policyRegistry], ["mainnetSpendGuard", spendGuard], ["mainnetAuditLog", auditLog]] as const) {
    if (!isAddress(addr)) {
      throw new OrgDeploymentError(`organization ${org.id} has an invalid ${name}: ${addr}`);
    }
  }

  return {
    orgId: org.id,
    chainId: org.mainnetChainId!,
    rpcUrl: org.mainnetRpcUrl!,
    policyRegistry: policyRegistry as `0x${string}`,
    spendGuard: spendGuard as `0x${string}`,
    auditLog: auditLog as `0x${string}`,
    ...chainClients(org.mainnetRpcUrl!, org.mainnetChainId!),
  };
}

/// Resolve the deployment owning an agent (agents carry organizationId).
/// Unknown agents fall back to the global deployment.
export async function resolveDeploymentForAgent(agentAddress: string): Promise<Deployment> {
  const agent = await prisma.agent.findUnique({
    where: { address: agentAddress.toLowerCase() },
    select: { organizationId: true },
  });
  return resolveDeployment(agent?.organizationId ?? null);
}
