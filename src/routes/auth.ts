import crypto from "node:crypto";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { isAddress } from "viem";
import { prisma } from "../db/client.js";
import { requireRole } from "../auth/clerkAuth.js";
import { productionGate } from "../auth/productionGate.js";
import { ensureUserWallet, walletStatusFor, clearCooldown } from "../auth/wallet.js";
import {
  INVITE_TTL_MS,
  claimPendingInvites,
  newInviteToken,
  normalizeEmail,
} from "../auth/invites.js";
import {
  expectsOnChainApproval,
  getApproverSyncStatus,
  setOnChainApprover,
} from "../chain/approverSync.js";
import { resolveDeployment } from "../chain/orgContracts.js";
import { createScopedToken } from "../auth/jwt.js";
import { issueWsTicket } from "../ws/ticket.js";
import { getCorrelationId } from "../auth/correlation.js";
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

const addressField = z.string().refine((v) => isAddress(v), "invalid EVM address");

const externalWalletBody = z.object({
  // null unlinks the wallet; an EVM address links (or replaces) it.
  address: addressField.nullable(),
}).strict();

const treasuryWalletBody = z.object({
  // null unlinks the treasury wallet; an EVM address links it.
  address: addressField.nullable(),
}).strict();

const scopedTokenBody = z.object({
  orgId: z.string().min(1),
}).strict();

// ── Helpers ──────────────────────────────────────────────────────────

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

// EVM addresses are case-insensitive; viem's isAddress accepts both cases,
// and we persist the exact string the user supplied.
function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}

// ── Routes ───────────────────────────────────────────────────────────

export async function authRoutes(app: FastifyInstance) {
  // ── Get current user profile + onboarding state ────────────────────
  //
  // This is the "what next" endpoint for a fresh login: an empty
  // `memberships` array means "no org yet" and the frontend prompts the
  // create-or-join choice (§4 of the auth architecture). Either path ends
  // with a Membership row — never with chain state.
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

    // Opportunistic catch-up for logins that raced the invite or for
    // Circle outages during first login: both are idempotent and cheap
    // once there is nothing to do.
    try {
      await claimPendingInvites(user.id, user.email);
    } catch {
      // ignore — the invite-accept endpoint retries explicitly
    }
    let walletAddress = user.walletAddress;
    let walletId = user.walletId;
    if (!walletAddress || !walletId) {
      try {
        const wallet = await ensureUserWallet(user.id, { name: user.label ?? user.email });
        if (wallet) {
          walletAddress = wallet.address;
          walletId = wallet.walletId;
        }
      } catch (err) {
        req.log.warn({ err, userId: user.id }, "Wallet provisioning failed — will retry on next request");
      }
    }

    const [memberships, pendingInvites] = await Promise.all([
      prisma.membership.findMany({
        where: { userId: user.id },
        include: {
          organization: {
            select: { id: true, name: true, slug: true, verified: true, treasuryWallet: true },
          },
        },
      }),
      prisma.invitation.count({
        where: {
          email: normalizeEmail(user.email),
          acceptedAt: null,
          expiresAt: { gt: new Date() },
        },
      }),
    ]);

    return reply.send({
      id: user.id,
      email: user.email,
      label: user.label,
      walletAddress,
      walletId,
      externalWalletAddress: user.externalWalletAddress,
      walletStatus: walletStatusFor({ walletAddress }),
      authMethod: "clerk",
      // Onboarding signal: empty means the account has no org — the client
      // offers "create a new organization" or "join via invite link".
      hasNoOrg: memberships.length === 0,
      pendingInvites,
      memberships: memberships.map((m) => ({
        org: m.organization,
        role: m.role,
      })),
    });
  });

  // ── Manually retry wallet provisioning ─────────────────────────────
  //
  // When automatic wallet creation fails (e.g. 429 rate limit), this
  // endpoint allows the user to explicitly retry. Clears the cooldown
  // and attempts fresh wallet creation.
  app.post("/auth/me/wallet", { preHandler: requireRole("viewer") }, async (req, reply) => {
    const user = await prisma.user.findUnique({ where: { id: req.operator!.id } });
    if (!user) {
      return reply.code(401).send({ error: "unauthorized", message: "User not found" });
    }

    if (user.walletAddress && user.walletId) {
      return reply.send({ walletAddress: user.walletAddress, walletId: user.walletId, status: "ready" });
    }

    req.log.info({ userId: user.id, walletAddress: user.walletAddress, walletId: user.walletId }, "Attempting wallet provisioning");

    // Clear any existing cooldown so this manual retry always attempts Circle
    clearCooldown(user.id);

    try {
      const wallet = await ensureUserWallet(user.id, { name: user.label ?? user.email });
      if (wallet) {
        req.log.info({ userId: user.id, walletAddress: wallet.address }, "Wallet provisioned successfully");
        return reply.send({ walletAddress: wallet.address, walletId: wallet.walletId, status: "ready" });
      }
      req.log.warn({ userId: user.id }, "ensureUserWallet returned null");
      return reply.send({ walletAddress: null, walletId: null, status: "unavailable" });
    } catch (err) {
      req.log.error({ err, userId: user.id }, "Manual wallet provisioning failed");
      return reply.code(503).send({ error: "wallet_error", message: "Wallet creation failed. Check Circle API credentials." });
    }
  });

  // ── Exchange session for scoped token (§6) ─────────────────────────
  //
  // The frontend holds a Clerk session; it calls this with the org it is
  // acting in and gets back a 15-minute token bound to (user, org, role,
  // wallet). Write routes accept the token as `Authorization: Bearer` and
  // authorize from its claims — the actual user and their role in the
  // relevant org, never a shared static secret. API-key callers (services
  // without Clerk accounts) don't use this endpoint.
  app.post("/auth/token", { preHandler: requireRole("viewer") }, async (req, reply) => {
    const parsed = scopedTokenBody.safeParse(req.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_request", message: parsed.error.issues[0]?.message });
    }

    // Scoped tokens are for humans: service credentials carry no user or
    // org context to scope into.
    const user = await prisma.user.findUnique({ where: { id: req.operator!.id } });
    if (!user) {
      return reply.code(403).send({ error: "forbidden", message: "Scoped tokens are only issued to human users" });
    }

    const membership = await prisma.membership.findUnique({
      where: { userId_organizationId: { userId: user.id, organizationId: parsed.data.orgId } },
    });
    if (!membership) {
      return reply.code(403).send({ error: "forbidden", message: "Not a member of this organization" });
    }

    const { token, expiresAt } = createScopedToken({
      id: user.id,
      email: user.email,
      orgId: membership.organizationId,
      role: membership.role,
      walletAddress: user.walletAddress,
    });

    return reply.send({
      token,
      tokenType: "Bearer",
      expiresAt,
      orgId: membership.organizationId,
      role: membership.role,
    });
  });

  // ── WebSocket feed ticket ──────────────────────────────────────────
  //
  // The /ws upgrade is not covered by header-based auth (browsers cannot
  // set custom headers on a WebSocket), so the client first exchanges its
  // authenticated REST session for this short-lived ticket and appends it
  // to the upgrade URL: /ws?ticket=... The connection's feed is scoped to
  // the operator's deployment for life (see ws/ticket.ts, ws/broadcast.ts).
  // Any role may hold the feed — viewing is not a privileged action — so
  // the gate matches /auth/token's.
  app.post("/auth/ws-ticket", { preHandler: requireRole("viewer") }, async (req, reply) => {
    const operator = req.operator!;
    // The ticket's orgId is the operator's REST-scoping org (scoped tokens
    // and Clerk+?orgId both land here), so the WS feed mirrors exactly what
    // this identity sees over REST — same resolveDeployment, same scoping.
    const { ticket, expiresAt } = issueWsTicket({ operatorId: operator.id, orgId: operator.orgId ?? null });
    return reply.send({ ticket, expiresAt: expiresAt.toISOString() });
  });

  // ── Link / unlink own external wallet ──────────────────────────────
  //
  // Optional add-on per §2: a user-linked wallet/multisig. Validated as an
  // EVM address; never replaces the embedded wallet.
  app.patch("/auth/me/external-wallet", { preHandler: requireRole("viewer") }, async (req, reply) => {
    const parsed = externalWalletBody.safeParse(req.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_request", message: parsed.error.issues[0]?.message });
    }

    const user = await prisma.user.findUnique({ where: { id: req.operator!.id } });
    if (!user) {
      return reply.code(401).send({ error: "unauthorized", message: "User not found" });
    }

    const updated = await prisma.user.update({
      where: { id: user.id },
      data: { externalWalletAddress: parsed.data.address },
      select: { externalWalletAddress: true },
    });

    return reply.send({ externalWalletAddress: updated.externalWalletAddress });
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
