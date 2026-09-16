import { prisma } from "../db/client.js";
import { spendGuardAbi } from "./abis/spendGuard.js";
import { ChainUnavailableError } from "./errors.js";
import type { Deployment } from "./orgContracts.js";
import { submitAsAdmin } from "./signing.js";

// ── Two-source-of-truth: app Membership role vs. on-chain approvers ──
//
// The chain is the source of truth for "can this address currently
// approve": SpendGuard.approvePending/rejectPending are `onlyApprover`, so
// only addresses in SpendGuard's `approvers` mapping can resolve
// escalations. The app's Membership table is the UX layer that stays
// consistent with it. All reads/writes here run against the TARGET ORG's
// deployment (per-org mainnet addressing), never implicitly global.
//
// Rules:
// - owner/admin/approver in the app EXPECT an on-chain grant; viewer (or
//   non-member) expects none. Admins and owners resolve escalations through
//   the same approve/reject routes, so they need the grant too.
// - Every promotion/demotion/removal flows through setOnChainApprover()
//   BEFORE the Membership row changes: if the tx submission fails, the DB
//   is untouched (fail closed, no drift). The audit row carries the sync
//   tx hash.
// - setApprover is admin-only on-chain, so the grant tx always comes from
//   the admin relayer (see signing.submitAsAdmin) — the person's wallet is
//   the GRANT TARGET, which is what the chain checks at approval time.
// - Only SpendGuard is synced. PolicyRegistry inherits the same
//   AccessControlLite base, but none of its functions are `onlyApprover` —
//   granting there would burn gas for an inert flag.

/// App roles that must hold an on-chain approver grant.
export function expectsOnChainApproval(role: string): boolean {
  return role === "owner" || role === "admin" || role === "approver";
}

/// Submit SpendGuard.setApprover on the target deployment. Returns the full
/// signing result for audit rows. Throws ChainUnavailableError so callers
/// fail closed with a retryable 503.
export async function setOnChainApprover(
  deployment: Deployment,
  walletAddress: string,
  allowed: boolean,
): Promise<{ txHash: string; signer: string; via: string }> {
  return submitAsAdmin(deployment, "spendGuard", "setApprover", [walletAddress, allowed]);
}

export type ApproverSyncRow = {
  userId: string;
  email: string;
  role: string;
  walletAddress: string | null;
  expected: boolean;
  onChain: boolean | null;
  inSync: boolean;
};

/// Compare every member's app-role expectation against chain state on the
/// target deployment in one multicall round-trip (same batching pattern as
/// readAgentPolicies). Members with no embedded wallet yet report
/// onChain: null — their grant is pending provisioning, not silently
/// assumed.
export async function getApproverSyncStatus(
  deployment: Deployment,
  organizationId: string,
): Promise<{ rows: ApproverSyncRow[]; outOfSync: number }> {
  const members = await prisma.membership.findMany({
    where: { organizationId },
    include: { user: { select: { id: true, email: true, walletAddress: true } } },
    orderBy: { createdAt: "asc" },
  });

  const wallets = members.map((m) => m.user.walletAddress);
  let onChain: (boolean | null)[];
  try {
    const results = await deployment.publicClient.multicall({
      contracts: wallets.map((w) => ({
        address: deployment.spendGuard,
        abi: spendGuardAbi,
        functionName: "approvers" as const,
        // The mapping getter answers false for addresses never granted, so
        // allowFailure: false is safe here (same reasoning as policies).
        args: [(w ?? "0x0000000000000000000000000000000000000000") as `0x${string}`],
      })),
      allowFailure: false,
    });
    onChain = wallets.map((w, i) => (w ? (results[i] as boolean) : null));
  } catch (err) {
    throw new ChainUnavailableError("could not read on-chain approver state", { cause: err });
  }

  const rows = members.map((m, i) => {
    const expected = expectsOnChainApproval(m.role);
    const chain = onChain[i]!;
    return {
      userId: m.user.id,
      email: m.user.email,
      role: m.role,
      walletAddress: m.user.walletAddress,
      expected,
      onChain: chain,
      // No wallet on record: in sync only when nothing is expected (a
      // viewer). An approver without a wallet is pending, never "in sync".
      inSync: m.user.walletAddress ? chain === expected : !expected,
    };
  });

  return { rows, outOfSync: rows.filter((r) => !r.inSync).length };
}
