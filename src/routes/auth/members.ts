import type { FastifyInstance } from "fastify";
import { prisma } from "../../db/client.js";
import { requireRole } from "../../auth/clerkAuth.js";
import { productionGate } from "../../auth/productionGate.js";
import { expectsOnChainApproval, getApproverSyncStatus, setOnChainApprover } from "../../chain/approverSync.js";
import { resolveDeployment } from "../../chain/orgContracts.js";
import { getCorrelationId } from "../../auth/correlation.js";
import { updateMemberRoleBody } from "./schemas.js";

// Server-side attribution for approver-grant changes, matching
// approvals.ts/policies.ts: the on-chain ApproverUpdated event can't name
// the human who triggered it, so the operator_actions row does, tied to
// the sync tx hash. Written only after the tx submits.
async function recordOperatorAction(
  operator: { id: string; label: string; role: string; walletAddress?: string },
  action: string,
  subjectId: string,
  signing: { txHash: string; signer: string; via: string },
) {
  await prisma.operatorAction.create({
    data: {
      operatorId: operator.id,
      operatorLabel: operator.label,
      role: operator.role,
      action,
      subjectId,
      txHash: signing.txHash,
      correlationId: getCorrelationId() ?? null,
      walletAddress: operator.walletAddress ?? null,
      signerAddress: signing.signer,
      signingVia: signing.via,
    },
  });
}

// ── Organization membership + on-chain approver sync routes ───────────
//
// GET   /auth/orgs/:orgId/members                 list members
// PATCH /auth/orgs/:orgId/members/:memberId/role  change a member's role
// DELETE /auth/orgs/:orgId/members/:memberId      remove a member
// GET   /auth/orgs/:orgId/approver-status         DB↔chain drift report
// POST  /auth/orgs/:orgId/approver-sync           heal approver drift
// GET   /auth/users                               list all users (admin)
export async function authMemberRoutes(app: FastifyInstance) {
  // ── List organization members ──────────────────────────────────────
  app.get<{ Params: { orgId: string } }>(
    "/auth/orgs/:orgId/members",
    { preHandler: requireRole("viewer") },
    async (req, reply) => {
      const { orgId } = req.params;

      // Verify the user is a member of this org
      const membership = await prisma.membership.findUnique({
        where: { userId_organizationId: { userId: req.operator!.id, organizationId: orgId } },
      });
      if (!membership) {
        return reply.code(403).send({ error: "forbidden", message: "Not a member of this organization" });
      }

      const members = await prisma.membership.findMany({
        where: { organizationId: orgId },
        include: {
          user: {
            select: { id: true, email: true, label: true, walletAddress: true, externalWalletAddress: true },
          },
        },
        orderBy: { createdAt: "asc" },
      });

      return reply.send({
        data: members.map((m) => ({
          user: m.user,
          role: m.role,
          joinedAt: m.createdAt,
        })),
      });
    },
  );

  // ── Update member role ─────────────────────────────────────────────
  //
  // Single flow, two steps: when the change crosses the approver boundary
  // (into or out of owner/admin/approver), the on-chain
  // SpendGuard.setApprover grant/revoke submits FIRST and the Membership
  // row updates only after submission succeeds. A chain failure leaves the
  // DB untouched (fail closed → 503, retryable) instead of drifting.
  // Members with no embedded wallet yet can't be granted on-chain — the DB
  // updates and the response flags onChain.synced: false so an admin heals
  // it via POST .../approver-sync once provisioning completes.
  app.patch<{ Params: { orgId: string; memberId: string } }>(
    "/auth/orgs/:orgId/members/:memberId/role",
    // Submits setApprover when crossing the approver boundary, so this is a
    // money-adjacent privileged write: gated like the other tx routes.
    { preHandler: [requireRole("admin"), productionGate()] },
    async (req, reply) => {
      const { orgId, memberId } = req.params;
      const parsed = updateMemberRoleBody.safeParse(req.body);
      if (!parsed.success) {
        return reply.code(400).send({ error: "invalid_request", message: parsed.error.issues[0]?.message });
      }

      // Verify requester is owner or admin
      const requesterMembership = await prisma.membership.findUnique({
        where: { userId_organizationId: { userId: req.operator!.id, organizationId: orgId } },
      });
      if (!requesterMembership || !["owner", "admin"].includes(requesterMembership.role)) {
        return reply.code(403).send({ error: "forbidden", message: "Insufficient permissions" });
      }

      // Only owners can promote to owner
      if (parsed.data.role === "owner" && requesterMembership.role !== "owner") {
        return reply.code(403).send({ error: "forbidden", message: "Only owners can transfer ownership" });
      }

      const targetMembership = await prisma.membership.findUnique({
        where: { userId_organizationId: { userId: memberId, organizationId: orgId } },
      });
      if (!targetMembership) {
        return reply.code(404).send({ error: "not_found", message: "Member not found" });
      }

      if (targetMembership.role === parsed.data.role) {
        return reply.send({ message: "Role unchanged", role: parsed.data.role, onChain: { synced: true } });
      }

      const targetUser = await prisma.user.findUnique({ where: { id: memberId } });
      const crossesBoundary =
        expectsOnChainApproval(targetMembership.role) !== expectsOnChainApproval(parsed.data.role);

      // Chain step first (fail-closed): a submission failure propagates as
      // ChainUnavailableError → 503, and the Membership row is never touched.
      // The grant lands on the ORG's deployment (per-org mainnet addressing).
      const deployment = await resolveDeployment(orgId);
      let sync: { txHash: string; signer: string; via: string } | null = null;
      if (crossesBoundary && targetUser?.walletAddress) {
        sync = await setOnChainApprover(
          deployment,
          targetUser.walletAddress,
          expectsOnChainApproval(parsed.data.role),
        );
      }

      await prisma.membership.update({
        where: { id: targetMembership.id },
        data: { role: parsed.data.role },
      });

      if (sync) {
        await recordOperatorAction(
          req.operator!,
          expectsOnChainApproval(parsed.data.role) ? "grant_approver" : "revoke_approver",
          memberId,
          sync,
        );
      }

      return reply.send({
        message: "Role updated",
        role: parsed.data.role,
        onChain:
          sync !== null
            ? { synced: true, txHash: sync.txHash, signer: sync.signer, via: sync.via }
            : crossesBoundary
              ? { synced: false, reason: "no_wallet" }
              : { synced: true },
      });
    },
  );

  // ── Approver sync status ───────────────────────────────────────────
  //
  // Drift detector for the two sources of truth: compares each member's
  // app-role expectation against SpendGuard.approvers in one multicall.
  // Read-only — healing is the POST below, never a side effect of reading.
  app.get<{ Params: { orgId: string } }>(
    "/auth/orgs/:orgId/approver-status",
    { preHandler: requireRole("viewer") },
    async (req, reply) => {
      const { orgId } = req.params;

      const membership = await prisma.membership.findUnique({
        where: { userId_organizationId: { userId: req.operator!.id, organizationId: orgId } },
      });
      if (!membership) {
        return reply.code(403).send({ error: "forbidden", message: "Not a member of this organization" });
      }

      const deployment = await resolveDeployment(orgId);
      return reply.send(await getApproverSyncStatus(deployment, orgId));
    },
  );

  // ── Heal approver drift ────────────────────────────────────────────
  //
  // Owner/Admin only. Brings every drifted member with a provisioned wallet
  // back in line (grant or revoke to match the app role); wallet-less
  // members are reported as skipped, never force-granted. Chain is the
  // enforcement truth, so the direction is always DB → chain here — the
  // app role is the admin's stated intent, the tx makes it real.
  app.post<{ Params: { orgId: string } }>(
    "/auth/orgs/:orgId/approver-sync",
    // Submits setApprover grants/revokes: gated like the other tx routes.
    { preHandler: [requireRole("admin"), productionGate()] },
    async (req, reply) => {
      const { orgId } = req.params;

      const membership = await prisma.membership.findUnique({
        where: { userId_organizationId: { userId: req.operator!.id, organizationId: orgId } },
      });
      if (!membership || !["owner", "admin"].includes(membership.role)) {
        return reply.code(403).send({ error: "forbidden", message: "Only owners and admins can sync approvers" });
      }

      const deployment = await resolveDeployment(orgId);
      const { rows } = await getApproverSyncStatus(deployment, orgId);
      const applied: Array<{ userId: string; expected: boolean; txHash: string; signer: string; via: string }> = [];
      const skipped: Array<{ userId: string; reason: string }> = [];

      for (const row of rows) {
        if (row.inSync) continue;
        if (!row.walletAddress) {
          skipped.push({ userId: row.userId, reason: "no_wallet" });
          continue;
        }
        // Fail-closed per member: a submission failure aborts the batch
        // with 503, leaving the remaining drift visible for a retry. Steps
        // already applied stay applied — each is independently correct.
        const sync = await setOnChainApprover(deployment, row.walletAddress, row.expected);
        await recordOperatorAction(
          req.operator!,
          row.expected ? "grant_approver" : "revoke_approver",
          row.userId,
          sync,
        );
        applied.push({ userId: row.userId, expected: row.expected, txHash: sync.txHash, signer: sync.signer, via: sync.via });
      }

      return reply.send({ applied, skipped });
    },
  );

  // ── Remove member from organization ────────────────────────────────
  app.delete<{ Params: { orgId: string; memberId: string } }>(
    "/auth/orgs/:orgId/members/:memberId",
    // Revokes the on-chain grant in the same flow: gated like the tx routes.
    { preHandler: [requireRole("admin"), productionGate()] },
    async (req, reply) => {
      const { orgId, memberId } = req.params;

      const requesterMembership = await prisma.membership.findUnique({
        where: { userId_organizationId: { userId: req.operator!.id, organizationId: orgId } },
      });
      if (!requesterMembership || !["owner", "admin"].includes(requesterMembership.role)) {
        return reply.code(403).send({ error: "forbidden", message: "Insufficient permissions" });
      }

      // Can't remove yourself
      if (memberId === req.operator!.id) {
        return reply.code(400).send({ error: "bad_request", message: "Cannot remove yourself" });
      }

      const targetMembership = await prisma.membership.findUnique({
        where: { userId_organizationId: { userId: memberId, organizationId: orgId } },
      });
      if (!targetMembership) {
        return reply.code(404).send({ error: "not_found", message: "Member not found" });
      }

      // Only owners can remove other owners
      if (targetMembership.role === "owner" && requesterMembership.role !== "owner") {
        return reply.code(403).send({ error: "forbidden", message: "Only owners can remove other owners" });
      }

      // Revoked members must lose on-chain approval in the same flow, or a
      // removed person could still sign. Chain step first (fail-closed):
      // submission failure → 503, membership untouched.
      const deployment = await resolveDeployment(orgId);
      const targetUser = await prisma.user.findUnique({ where: { id: memberId } });
      let sync: { txHash: string; signer: string; via: string } | null = null;
      if (expectsOnChainApproval(targetMembership.role) && targetUser?.walletAddress) {
        sync = await setOnChainApprover(deployment, targetUser.walletAddress, false);
      }

      await prisma.membership.delete({ where: { id: targetMembership.id } });

      if (sync) {
        await recordOperatorAction(req.operator!, "revoke_approver", memberId, sync);
      }

      return reply.send({
        message: "Member removed",
        onChain:
          sync !== null
            ? { synced: true, txHash: sync.txHash, signer: sync.signer, via: sync.via }
            : expectsOnChainApproval(targetMembership.role)
              ? { synced: false, reason: "no_wallet" }
              : { synced: true },
      });
    },
  );

  // ── List all users (admin only) ────────────────────────────────────
  app.get("/auth/users", { preHandler: requireRole("admin") }, async () => {
    const users = await prisma.user.findMany({
      select: {
        id: true,
        email: true,
        label: true,
        walletAddress: true,
        externalWalletAddress: true,
        createdAt: true,
      },
      orderBy: { createdAt: "desc" },
    });
    return { data: users };
  });
}
