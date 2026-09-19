import { createPublicClient, createWalletClient, defineChain } from "viem";
import type { Account, Chain, PublicClient, Transport, WalletClient } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { isAddress } from "viem";
import { config } from "../config.js";
import { arcTransport } from "./client.js";
import { prisma } from "../db/client.js";

/// Mirrors PolicyRegistry.RESERVATION_TTL (7 days). Lives here — next to
/// the deployment/contract plumbing — rather than in the ABI file so both
/// the indexer (stamping expiresAt from SpendReserved) and the expiry
/// sweeper (fallback for rows without a stamp) share one constant. Update
/// together with the contract if the TTL ever changes.
export const RESERVATION_TTL_SECONDS = 7 * 24 * 60 * 60;

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

/// Stable identifier for a deployment, used to scope DB rows that would
/// otherwise collide across deployments: pending requests (on-chain request
/// ids are per-deployment counters) and indexer checkpoints (blocks are
/// per-chain). Processed-log claims are deliberately NOT keyed by
/// deployment: (txHash, logIndex) is globally unique because identical
/// signed tx bytes across deployments are cryptographically impossible
/// (different contracts ⇒ different bytes ⇒ different hash), and a shared
/// claim doubles as cross-watcher dedup if two watcher configs ever
/// overlap on the same log. "global" names the env-configured
/// deployment; per-org deployments are named by their org id, which the DB
/// schema guarantees is unique.
export function deploymentKey(deployment: Deployment): string {
  return deployment.orgId ?? "global";
}

/// Every deployment this server instance serves: the global env deployment,
/// plus every org with a COMPLETE mainnet deployment when running in
/// mainnet mode (testnet is one shared playground — see resolveDeployment).
/// Used to start one indexer set per deployment so on-chain events from
/// org contracts reach the DB; resolveDeployment's five-field fail-closed
/// rule is reused so partially-configured orgs are never probed here.
export async function listServedDeployments(): Promise<Deployment[]> {
  const deployments: Deployment[] = [globalDeployment()];

  if (config.WARDEN_NETWORK !== "mainnet") return deployments;

  const orgs = await prisma.organization.findMany({
    where: {
      mainnetPolicyRegistry: { not: null },
      mainnetSpendGuard: { not: null },
      mainnetAuditLog: { not: null },
      mainnetRpcUrl: { not: null },
      mainnetChainId: { not: null },
    },
    select: {
      id: true,
      mainnetPolicyRegistry: true,
      mainnetSpendGuard: true,
      mainnetAuditLog: true,
      mainnetRpcUrl: true,
      mainnetChainId: true,
    },
  });

  for (const org of orgs) {
    // Reuse the resolver so address validation and client construction stay
    // in exactly one code path. A misconfigured org that slipped past the
    // where-clause (e.g. an invalid address) surfaces OrgDeploymentError —
    // let it propagate: boot must not silently skip an org's events.
    const deployment = await resolveDeployment(org.id);
    if (!deployments.some((d) => d.orgId === deployment.orgId)) {
      deployments.push(deployment);
    }
  }

  return deployments;
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

  // arcTransport layers the ARC_RPC_FALLBACK_URLS failover onto every read
  // and write this deployment makes (see chain/client.ts).
  const transport = arcTransport(rpcUrl);
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
