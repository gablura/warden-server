/// One-time backfill for the tenant-scoping change (hardening review §7
/// follow-up): agents indexed BEFORE the indexers began stamping
/// Agent.organizationId have no org stamp — on mainnet they stay globally
/// visible until their next on-chain event restamps them. This script
/// closes that window by reading each per-org deployment's historical
/// events and stamping the unstamped rows those events name.
///
/// Safety properties (deliberately conservative):
///   - Stamps ONLY rows whose organizationId is null (unstamped), and only
///     when a per-org deployment's own history names the agent. The global
///     deployment's stamp IS null, so global rows need no action.
///   - Never re-stamps a stamped row, never clears a stamp, never touches
///     caps/spend/status — org ownership only.
///   - Does not create missing agent rows: the watchers create those from
///     the same events on first sight; a missing row is data-completeness
///     that self-heals, not a tenant-boundary hole. They are REPORTED so
///     the operator knows what is still unseen.
///   - Idempotent and safe to re-run, including while the server is live
///     (watchers stamp on create only — the same rule this follows).
///   - Exits nonzero if any block range could not be read: a partial
///     history must be loud, because a silently incomplete stamp leaves an
///     org's agent globally visible.
///
/// On testnet this is a no-op (listServedDeployments returns only the
/// global deployment) — run it right after enabling per-org deployments.
///
/// Run:  npx tsx scripts/backfill-agent-orgs.ts [--dry-run]

import { config } from "../src/config.js";
import { prisma } from "../src/db/client.js";
import { listServedDeployments, type Deployment } from "../src/chain/orgContracts.js";
import { policyRegistryAbi } from "../src/chain/abis/policyRegistry.js";
import { spendGuardAbi } from "../src/chain/abis/spendGuard.js";

const dryRun = process.argv.includes("--dry-run");

/// Block-range size for historical getLogs sweeps. Small enough to stay
/// under RPC providers' range limits; the sweep is one-time, so pacing
/// matters less than reliability.
const SWEEP_CHUNK = 50_000n;

async function sweepAgents(deployment: Deployment): Promise<string[]> {
  const agents = new Set<string>();

  // PolicySet lives on the org's PolicyRegistry; every payment event lives
  // on its SpendGuard. Both name the agent — a deployment "owns" an agent
  // if either contract's history mentions it (same rule the watchers use).
  const sources = [
    { address: deployment.policyRegistry, abi: policyRegistryAbi, eventName: "PolicySet" as const },
    { address: deployment.spendGuard, abi: spendGuardAbi, eventName: "PaymentApproved" as const },
    { address: deployment.spendGuard, abi: spendGuardAbi, eventName: "PaymentBlocked" as const },
    { address: deployment.spendGuard, abi: spendGuardAbi, eventName: "PaymentEscalated" as const },
  ];

  const head = await deployment.publicClient.getBlockNumber();

  for (const src of sources) {
    for (let from = 0n; from <= head; from += SWEEP_CHUNK) {
      const to = from + SWEEP_CHUNK - 1n > head ? head : from + SWEEP_CHUNK - 1n;
      const logs = await deployment.publicClient.getContractEvents({
        address: src.address,
        abi: src.abi,
        eventName: src.eventName as never,
        fromBlock: from,
        toBlock: to,
      });
      for (const log of logs) {
        const agent = (log.args as { agent?: string }).agent;
        if (agent) agents.add(agent.toLowerCase());
      }
    }
  }

  return [...agents];
}

async function backfillDeployment(deployment: Deployment): Promise<void> {
  const label = deployment.orgId ?? "global";

  // The global deployment's stamp is null — nothing to backfill for it.
  if (deployment.orgId === null) {
    console.log(`[global] skipped: the global deployment's org stamp is null by definition`);
    return;
  }

  console.log(`[org:${label}] sweeping historical events for agent addresses...`);
  const agents = await sweepAgents(deployment);
  console.log(`[org:${label}] ${agents.length} distinct agent address(es) named by this deployment's history`);

  if (agents.length === 0) return;

  const unstamped = await prisma.agent.findMany({
    where: { address: { in: agents }, organizationId: null },
    select: { address: true },
  });

  const missing = await prisma.agent.findMany({
    where: { address: { in: agents } },
    select: { address: true },
  });
  const known = new Set(missing.map((r) => r.address));
  const notInDb = agents.filter((a) => !known.has(a));

  if (notInDb.length > 0) {
    console.warn(
      `[org:${label}] ${notInDb.length} agent(s) have no DB row yet — the watchers will create them on their next event:`,
    );
    for (const a of notInDb) console.warn(`    ${a}`);
  }

  if (unstamped.length === 0) {
    console.log(`[org:${label}] nothing to stamp (all rows already stamped or absent)`);
    return;
  }

  if (dryRun) {
    console.log(`[org:${label}] DRY RUN — would stamp ${unstamped.length} row(s):`);
    for (const r of unstamped) console.log(`    ${r.address} -> ${deployment.orgId}`);
    return;
  }

  // Stamp one UPDATE per address. A single updateMany over the whole set
  // would be faster, but per-row updates keep a concurrent watcher race
  // harmless at row granularity and make partial failures precisely
  // reportable. The where clause re-checks organizationId: null, so a
  // row stamped between the findMany and the update is left alone.
  let stamped = 0;
  for (const row of unstamped) {
    const result = await prisma.agent.updateMany({
      where: { address: row.address, organizationId: null },
      data: { organizationId: deployment.orgId },
    });
    stamped += result.count;
  }
  console.log(`[org:${label}] stamped ${stamped} agent row(s) with organizationId=${deployment.orgId}`);
}

async function main() {
  console.log(`backfill-agent-orgs ${dryRun ? "(dry run)" : ""} — network: ${config.WARDEN_NETWORK}`);

  const deployments = await listServedDeployments();
  console.log(`${deployments.length} served deployment(s)`);

  let failed = false;
  for (const deployment of deployments) {
    try {
      await backfillDeployment(deployment);
    } catch (err) {
      failed = true;
      console.error(`[org:${deployment.orgId ?? "global"}] FAILED — stamps from this deployment are incomplete:`, err);
    }
  }

  await prisma.$disconnect();
  if (failed) {
    console.error("one or more deployments could not be fully swept — re-run after fixing the error; already-stamped rows are safe");
    process.exit(1);
  }
  console.log("done");
}

void main();
