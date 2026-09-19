import type { FastifyInstance } from "fastify";
import { prisma } from "../../db/client.js";
import { requireRole } from "../../auth/clerkAuth.js";
import { ensureUserWallet, walletStatusFor, clearCooldown } from "../../auth/wallet.js";
import { claimPendingInvites, normalizeEmail } from "../../auth/invites.js";
import { createScopedToken } from "../../auth/jwt.js";
import { issueWsTicket } from "../../ws/ticket.js";
import { externalWalletBody, scopedTokenBody } from "./schemas.js";

// ── "My account" + credential-issuing routes ─────────────────────────
//
// GET /auth/me                 profile + onboarding state
// POST /auth/me/wallet         manual wallet provisioning retry
// PATCH /auth/me/external-wallet link/unlink an external wallet
// POST /auth/token             exchange the session for a scoped token
// POST /auth/ws-ticket         short-lived ticket for the /ws upgrade
export async function authMeRoutes(app: FastifyInstance) {
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
}
