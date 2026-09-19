import type { FastifyInstance } from "fastify";
import { prisma } from "../../db/client.js";
import { requireRole } from "../../auth/clerkAuth.js";
import { INVITE_TTL_MS, newInviteToken, normalizeEmail } from "../../auth/invites.js";
import { config } from "../../config.js";
import { inviteMemberBody } from "./schemas.js";

// ── Invitation routes ─────────────────────────────────────────────────
//
// POST   /auth/orgs/:orgId/invite            invite a member (owner/admin)
// GET    /auth/orgs/:orgId/invites           list org invites (owner/admin)
// DELETE /auth/orgs/:orgId/invites/:inviteId revoke a pending invite
// GET    /auth/invites/pending               list my pending invites
// POST   /auth/invites/:token/accept         accept an invite
export async function authInviteRoutes(app: FastifyInstance) {
  // ── Invite member to organization ──────────────────────────────────
  //
  // Owner/Admin can invite new members with a role (default `viewer`).
  // Always persists a token-based Invitation row so joining works with or
  // without Clerk email delivery; when Clerk is configured the invite is
  // additionally sent through Clerk's email system. Re-inviting a pending
  // email refreshes the token/expiry/role instead of stacking rows.
  app.post<{ Params: { orgId: string } }>(
    "/auth/orgs/:orgId/invite",
    { preHandler: requireRole("admin") },
    async (req, reply) => {
      const { orgId } = req.params;
      const parsed = inviteMemberBody.safeParse(req.body);
      if (!parsed.success) {
        return reply.code(400).send({ error: "invalid_request", message: parsed.error.issues[0]?.message });
      }

      // Verify the user is an admin/owner of this org
      const membership = await prisma.membership.findUnique({
        where: { userId_organizationId: { userId: req.operator!.id, organizationId: orgId } },
      });
      if (!membership || !["owner", "admin"].includes(membership.role)) {
        return reply.code(403).send({ error: "forbidden", message: "Only owners and admins can invite members" });
      }

      const org = await prisma.organization.findUnique({ where: { id: orgId } });
      if (!org) {
        return reply.code(404).send({ error: "not_found", message: "Organization not found" });
      }

      const email = normalizeEmail(parsed.data.email);

      // Skip invites for existing members — inviting is for joining.
      const alreadyMember = await prisma.user.findUnique({ where: { email } }).then((u) =>
        u
          ? prisma.membership.findUnique({
              where: { userId_organizationId: { userId: u.id, organizationId: orgId } },
            })
          : null,
      );
      if (alreadyMember) {
        return reply.code(409).send({ error: "conflict", message: "This user is already a member of the organization" });
      }

      // Refresh a still-pending invite for the same email instead of
      // creating a duplicate; otherwise mint a fresh token.
      const existing = await prisma.invitation.findFirst({
        where: { organizationId: orgId, email, acceptedAt: null, expiresAt: { gt: new Date() } },
      });

      const invite = existing
        ? await prisma.invitation.update({
            where: { id: existing.id },
            data: {
              role: parsed.data.role,
              token: newInviteToken(),
              expiresAt: new Date(Date.now() + INVITE_TTL_MS),
              createdById: req.operator!.id,
            },
          })
        : await prisma.invitation.create({
            data: {
              organizationId: orgId,
              email,
              role: parsed.data.role,
              token: newInviteToken(),
              expiresAt: new Date(Date.now() + INVITE_TTL_MS),
              createdById: req.operator!.id,
            },
          });
      // Send invite via Clerk if configured (best-effort — the token link
      // below is the delivery mechanism that always works).
      let clerkSent = false;
      if (config.CLERK_SECRET_KEY && org.clerkId.startsWith("org_")) {
        try {
          const res = await fetch(`https://api.clerk.com/v1/organizations/${org.clerkId}/invitations`, {
            method: "POST",
            headers: {
              Authorization: `Bearer ${config.CLERK_SECRET_KEY}`,
              "Content-Type": "application/json",
            },
            body: JSON.stringify({
              email_address: email,
              role: parsed.data.role,
            }),
          });
          clerkSent = res.ok;
          if (!res.ok) {
            req.log.warn({ orgId, email, status: res.status }, "Clerk invitation send failed — token link still valid");
          }
        } catch (err) {
          req.log.warn({ err }, "Failed to send Clerk invitation — token link still valid");
        }
      }

      return reply.code(201).send({
        message: `Invitation for ${email} as ${invite.role}`,
        inviteToken: invite.token,
        // The frontend prefixes its own origin to build the shareable link.
        invitePath: `/auth/invites/${invite.token}/accept`,
        expiresAt: invite.expiresAt,
        clerkEmailSent: clerkSent,
      });
    },
  );

  // ── List organization invites (owner/admin) ─────────────────────────
  app.get<{ Params: { orgId: string } }>(
    "/auth/orgs/:orgId/invites",
    { preHandler: requireRole("admin") },
    async (req, reply) => {
      const { orgId } = req.params;

      const membership = await prisma.membership.findUnique({
        where: { userId_organizationId: { userId: req.operator!.id, organizationId: orgId } },
      });
      if (!membership || !["owner", "admin"].includes(membership.role)) {
        return reply.code(403).send({ error: "forbidden", message: "Only owners and admins can view invites" });
      }

      const invites = await prisma.invitation.findMany({
        where: { organizationId: orgId },
        orderBy: { createdAt: "desc" },
      });

      const now = Date.now();
      return reply.send({
        data: invites.map((i) => ({
          id: i.id,
          email: i.email,
          role: i.role,
          expiresAt: i.expiresAt,
          acceptedAt: i.acceptedAt,
          createdAt: i.createdAt,
          status: i.acceptedAt !== null ? "accepted" : i.expiresAt.getTime() <= now ? "expired" : "pending",
        })),
      });
    },
  );

  // ── Revoke a pending invite (owner/admin) ───────────────────────────
  app.delete<{ Params: { orgId: string; inviteId: string } }>(
    "/auth/orgs/:orgId/invites/:inviteId",
    { preHandler: requireRole("admin") },
    async (req, reply) => {
      const { orgId, inviteId } = req.params;

      const membership = await prisma.membership.findUnique({
        where: { userId_organizationId: { userId: req.operator!.id, organizationId: orgId } },
      });
      if (!membership || !["owner", "admin"].includes(membership.role)) {
        return reply.code(403).send({ error: "forbidden", message: "Only owners and admins can revoke invites" });
      }

      const invite = await prisma.invitation.findFirst({
        where: { id: inviteId, organizationId: orgId, acceptedAt: null },
      });
      if (!invite) {
        return reply.code(404).send({ error: "not_found", message: "Pending invite not found" });
      }

      await prisma.invitation.delete({ where: { id: invite.id } });
      return reply.send({ message: "Invite revoked" });
    },
  );

  // ── List my pending invites ────────────────────────────────────────
  //
  // The join half of the §4 choice: a fresh login with no org calls this to
  // show "you've been invited to X as Y" instead of only offering create.
  app.get("/auth/invites/pending", { preHandler: requireRole("viewer") }, async (req, reply) => {
    const user = await prisma.user.findUnique({ where: { id: req.operator!.id } });
    if (!user) {
      return reply.code(401).send({ error: "unauthorized", message: "User not found" });
    }

    const invites = await prisma.invitation.findMany({
      where: {
        email: normalizeEmail(user.email),
        acceptedAt: null,
        expiresAt: { gt: new Date() },
      },
      include: {
        organization: { select: { id: true, name: true, slug: true } },
      },
      orderBy: { createdAt: "desc" },
    });

    return reply.send({
      data: invites.map((i) => ({
        token: i.token,
        role: i.role,
        expiresAt: i.expiresAt,
        organization: i.organization,
      })),
    });
  });

  // ── Accept an invite ───────────────────────────────────────────────
  //
  // Join-via-invite-link: creates the Membership with the role the inviting
  // admin set (default `viewer`). Idempotent — accepting twice, or accepting
  // when already a member, returns the membership without duplicating.
  // Creates a Membership and ONLY a Membership: no on-chain grant happens
  // here (that sync is §5's job, intentionally separate from joining).
  app.post<{ Params: { token: string } }>(
    "/auth/invites/:token/accept",
    { preHandler: requireRole("viewer") },
    async (req, reply) => {
      const invite = await prisma.invitation.findUnique({
        where: { token: req.params.token },
        include: {
          organization: { select: { id: true, name: true, slug: true } },
        },
      });

      if (!invite) {
        return reply.code(404).send({ error: "not_found", message: "Invite not found" });
      }
      if (invite.acceptedAt !== null) {
        return reply.code(410).send({ error: "gone", message: "This invite was already accepted" });
      }
      if (invite.expiresAt.getTime() <= Date.now()) {
        return reply.code(410).send({ error: "gone", message: "This invite has expired" });
      }

      const user = await prisma.user.findUnique({ where: { id: req.operator!.id } });
      if (!user) {
        return reply.code(401).send({ error: "unauthorized", message: "User not found" });
      }
      if (normalizeEmail(user.email) !== invite.email) {
        return reply.code(403).send({
          error: "forbidden",
          message: "This invite was sent to a different email address",
        });
      }

      const membership = await prisma.membership.upsert({
        where: { userId_organizationId: { userId: user.id, organizationId: invite.organizationId } },
        create: { userId: user.id, organizationId: invite.organizationId, role: invite.role },
        update: {},
      });

      await prisma.invitation.update({
        where: { id: invite.id },
        data: { acceptedAt: new Date() },
      });

      return reply.send({
        organization: invite.organization,
        role: membership.role,
      });
    },
  );
}
