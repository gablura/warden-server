import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { prisma } from "../db/client.js";
import { requireRole } from "../auth/clerkAuth.js";
import { createWallet } from "../auth/wallet.js";
import { config } from "../config.js";

// ── Schemas ──────────────────────────────────────────────────────────

const createOrgBody = z.object({
  name: z.string().min(2).max(100),
}).strict();

const inviteMemberBody = z.object({
  email: z.string().email(),
  role: z.enum(["admin", "approver", "viewer"]).default("viewer"),
}).strict();

const updateMemberRoleBody = z.object({
  role: z.enum(["owner", "admin", "approver", "viewer"]),
}).strict();

// ── Routes ───────────────────────────────────────────────────────────

export async function authRoutes(app: FastifyInstance) {
  // ── Get current user profile ───────────────────────────────────────
  app.get("/auth/me", { preHandler: requireRole("viewer") }, async (req, reply) => {
    const operator = req.operator!;
    const user = await prisma.user.findUnique({ where: { id: operator.id } });

    if (!user) {
      // API key user — return minimal profile from the credential
      return reply.send({
        id: operator.id,
        label: operator.label,
        role: operator.role,
        authMethod: "api_key",
        memberships: [],
      });
    }

    const memberships = await prisma.membership.findMany({
      where: { userId: user.id },
      include: { organization: { select: { id: true, name: true, slug: true, verified: true } } },
    });

    return reply.send({
      id: user.id,
      email: user.email,
      label: user.label,
      walletAddress: user.walletAddress,
      authMethod: "clerk",
      memberships: memberships.map((m) => ({
        org: m.organization,
        role: m.role,
      })),
    });
  });

  // ── Create organization ────────────────────────────────────────────
  //
  // The creating user becomes the Owner. If Clerk is configured,
  // also creates the org in Clerk for their managed UI.
  app.post("/auth/orgs", { preHandler: requireRole("viewer") }, async (req, reply) => {
    const parsed = createOrgBody.safeParse(req.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_request", message: parsed.error.issues[0]?.message });
    }

    const userId = req.operator!.id;
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      return reply.code(401).send({ error: "unauthorized", message: "User not found" });
    }

    const slug = parsed.data.name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, "");

    // Create in Clerk if configured
    let clerkOrgId = `local_${Date.now()}`;
    if (config.CLERK_SECRET_KEY) {
      try {
        const res = await fetch("https://api.clerk.com/v1/organizations", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${config.CLERK_SECRET_KEY}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            name: parsed.data.name,
            slug,
            created_by: user.clerkId,
          }),
        });
        if (res.ok) {
          const clerkOrg = await res.json() as { id: string };
          clerkOrgId = clerkOrg.id;
        }
      } catch (err) {
        req.log.warn({ err }, "Failed to create Clerk org — using local ID");
      }
    }

    // Create org + membership in a transaction
    const result = await prisma.$transaction(async (tx) => {
      const org = await tx.organization.create({
        data: {
          clerkId: clerkOrgId,
          name: parsed.data.name,
          slug,
        },
      });

      await tx.membership.create({
        data: {
          userId,
          organizationId: org.id,
          role: "owner",
        },
      });

      return org;
    });

    return reply.code(201).send({
      id: result.id,
      name: result.name,
      slug: result.slug,
      role: "owner",
    });
  });

  // ── List user's organizations ──────────────────────────────────────
  app.get("/auth/orgs", { preHandler: requireRole("viewer") }, async (req, reply) => {
    const userId = req.operator!.id;

    const memberships = await prisma.membership.findMany({
      where: { userId },
      include: {
        organization: {
          select: { id: true, name: true, slug: true, verified: true },
        },
      },
    });

    return reply.send({
      data: memberships.map((m) => ({
        ...m.organization,
        role: m.role,
      })),
    });
  });

  // ── Invite member to organization ──────────────────────────────────
  //
  // Owner/Admin can invite new members. If Clerk is configured,
  // sends the invite via Clerk's email system.
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

      // Send invite via Clerk if configured
      if (config.CLERK_SECRET_KEY && org.clerkId.startsWith("org_")) {
        try {
          const res = await fetch(`https://api.clerk.com/v1/organizations/${org.clerkId}/invitations`, {
            method: "POST",
            headers: {
              Authorization: `Bearer ${config.CLERK_SECRET_KEY}`,
              "Content-Type": "application/json",
            },
            body: JSON.stringify({
              email_address: parsed.data.email,
              role: parsed.data.role,
            }),
          });
          if (res.ok) {
            return reply.send({ message: `Invitation sent to ${parsed.data.email}` });
          }
        } catch (err) {
          req.log.warn({ err }, "Failed to send Clerk invitation");
        }
      }

      // Fallback: create a pending membership (user will be added on first login)
      // For now, return a message that the invite was recorded
      req.log.info({ orgId, email: parsed.data.email, role: parsed.data.role }, "Invite recorded (Clerk not configured)");
      return reply.send({ message: `Invite recorded for ${parsed.data.email} as ${parsed.data.role}. Clerk invitation email not sent.` });
    },
  );

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
            select: { id: true, email: true, label: true, walletAddress: true },
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
  app.patch<{ Params: { orgId: string; memberId: string } }>(
    "/auth/orgs/:orgId/members/:memberId/role",
    { preHandler: requireRole("admin") },
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

      await prisma.membership.update({
        where: { id: targetMembership.id },
        data: { role: parsed.data.role },
      });

      return reply.send({ message: "Role updated", role: parsed.data.role });
    },
  );

  // ── Remove member from organization ────────────────────────────────
  app.delete<{ Params: { orgId: string; memberId: string } }>(
    "/auth/orgs/:orgId/members/:memberId",
    { preHandler: requireRole("admin") },
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

      await prisma.membership.delete({ where: { id: targetMembership.id } });

      return reply.send({ message: "Member removed" });
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
        createdAt: true,
      },
      orderBy: { createdAt: "desc" },
    });
    return { data: users };
  });
}
