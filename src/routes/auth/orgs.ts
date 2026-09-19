import crypto from "node:crypto";
import type { FastifyInstance } from "fastify";
import { prisma } from "../../db/client.js";
import { requireRole } from "../../auth/clerkAuth.js";
import { config } from "../../config.js";
import { createOrgBody, treasuryWalletBody } from "./schemas.js";

// Lowercase, strip anything outside [a-z0-9], collapse to dashes: used to
// derive an organization's unique slug from its display name.
function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}

// ── Organization lifecycle routes ─────────────────────────────────────
//
// POST  /auth/orgs                    create org (creator becomes owner)
// GET   /auth/orgs                    list the caller's organizations
// PATCH /auth/orgs/:orgId/treasury    link/unlink the treasury wallet
export async function authOrgRoutes(app: FastifyInstance) {
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

    const baseSlug = slugify(parsed.data.name);

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
            slug: baseSlug,
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
    // Create org + owner membership in a transaction. A slug collision
    // (two orgs with the same name) gets one suffixed retry, then a 409.
    const createWithSlug = (slug: string) =>
      prisma.$transaction(async (tx) => {
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

    try {
      const result = await createWithSlug(baseSlug);
      return reply.code(201).send({
        id: result.id,
        name: result.name,
        slug: result.slug,
        role: "owner",
      });
    } catch (err) {
      if ((err as { code?: string }).code !== "P2002") throw err;
      const retrySlug = `${baseSlug}-${crypto.randomBytes(3).toString("hex")}`;
      try {
        const result = await createWithSlug(retrySlug);
        return reply.code(201).send({
          id: result.id,
          name: result.name,
          slug: result.slug,
          role: "owner",
        });
      } catch (retryErr) {
        if ((retryErr as { code?: string }).code === "P2002") {
          return reply.code(409).send({ error: "conflict", message: "An organization with this name already exists" });
        }
        throw retryErr;
      }
    }
  });

  // ── List user's organizations ──────────────────────────────────────
  app.get("/auth/orgs", { preHandler: requireRole("viewer") }, async (req, reply) => {
    const userId = req.operator!.id;

    const memberships = await prisma.membership.findMany({
      where: { userId },
      include: {
        organization: {
          select: { id: true, name: true, slug: true, verified: true, treasuryWallet: true },
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

  // ── Link / unlink org treasury wallet ──────────────────────────────
  //
  // Optional add-on per §2: an external treasury wallet/multisig linked at
  // the organization level. Owner/Admin only. Clerk-managed orgs mirror
  // nothing here — this is product state, not identity state.
  app.patch<{ Params: { orgId: string } }>(
    "/auth/orgs/:orgId/treasury",
    { preHandler: requireRole("admin") },
    async (req, reply) => {
      const { orgId } = req.params;
      const parsed = treasuryWalletBody.safeParse(req.body);
      if (!parsed.success) {
        return reply.code(400).send({ error: "invalid_request", message: parsed.error.issues[0]?.message });
      }

      const membership = await prisma.membership.findUnique({
        where: { userId_organizationId: { userId: req.operator!.id, organizationId: orgId } },
      });
      if (!membership || !["owner", "admin"].includes(membership.role)) {
        return reply.code(403).send({ error: "forbidden", message: "Only owners and admins can link a treasury wallet" });
      }

      const org = await prisma.organization.findUnique({ where: { id: orgId } });
      if (!org) {
        return reply.code(404).send({ error: "not_found", message: "Organization not found" });
      }

      const updated = await prisma.organization.update({
        where: { id: orgId },
        data: { treasuryWallet: parsed.data.address },
        select: { treasuryWallet: true },
      });

      return reply.send({ treasuryWallet: updated.treasuryWallet });
    },
  );
}
