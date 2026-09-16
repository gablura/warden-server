import type { FastifyInstance } from "fastify";
import { Webhook } from "svix";
import { prisma } from "../db/client.js";
import { config } from "../config.js";
import { claimPendingInvites, normalizeEmail } from "../auth/invites.js";

// ── Clerk Webhook Events ─────────────────────────────────────────────
//
// Syncs Clerk-managed users, organizations, and memberships into the
// local Prisma database. This keeps the backend in sync when data
// changes via Clerk's dashboard or managed UI.

interface ClerkWebhookEvent {
  type: string;
  data: Record<string, unknown>;
}

// ── Route ────────────────────────────────────────────────────────────

export async function clerkWebhookRoutes(app: FastifyInstance) {
  app.post("/webhooks/clerk", async (req, reply) => {
    // Clerk webhook secret is required
    if (!config.CLERK_WEBHOOK_SECRET) {
      return reply.code(503).send({ error: "webhooks_disabled", message: "CLERK_WEBHOOK_SECRET not configured" });
    }

    // Verify svix signature
    const svixId = req.headers["svix-id"] as string | undefined;
    const svixTimestamp = req.headers["svix-timestamp"] as string | undefined;
    const svixSignature = req.headers["svix-signature"] as string | undefined;

    if (!svixId || !svixTimestamp || !svixSignature) {
      return reply.code(400).send({ error: "missing_headers", message: "Missing svix headers" });
    }

    // Get raw body for signature verification
    const body = JSON.stringify(req.body);

    const wh = new Webhook(config.CLERK_WEBHOOK_SECRET);
    let event: ClerkWebhookEvent;

    try {
      const verified = wh.verify(body, {
        "svix-id": svixId,
        "svix-timestamp": svixTimestamp,
        "svix-signature": svixSignature,
      });
      event = verified as unknown as ClerkWebhookEvent;
    } catch (err) {
      req.log.warn({ err }, "Clerk webhook signature verification failed");
      return reply.code(401).send({ error: "invalid_signature", message: "Invalid webhook signature" });
    }

    req.log.info({ type: event.type }, "Clerk webhook received");

    try {
      switch (event.type) {
        case "user.created":
        case "user.updated":
          await handleUserEvent(event);
          break;
        case "user.deleted":
          await handleUserDeleted(event);
          break;
        case "organization.created":
        case "organization.updated":
          await handleOrganizationEvent(event);
          break;
        case "organization.deleted":
          await handleOrganizationDeleted(event);
          break;
        case "organizationMembership.created":
        case "organizationMembership.updated":
          await handleMembershipEvent(event);
          break;
        case "organizationMembership.deleted":
          await handleMembershipDeleted(event);
          break;
        default:
          req.log.debug({ type: event.type }, "Unhandled Clerk webhook event type");
      }
    } catch (err) {
      req.log.error({ err, type: event.type }, "Failed to process Clerk webhook event");
      return reply.code(500).send({ error: "processing_failed", message: "Failed to process event" });
    }

    return reply.code(200).send({ received: true });
  });
}

// ── Event Handlers ───────────────────────────────────────────────────

async function handleUserEvent(event: ClerkWebhookEvent) {
  const data = event.data;
  const clerkId = data.id as string;
  if (!clerkId) return;

  const email = Array.isArray(data.email_addresses)
    ? (data.email_addresses as Array<{ email_address: string }>)[0]?.email_address
    : undefined;

  const firstName = data.first_name as string | undefined;
  const lastName = data.last_name as string | undefined;
  const label = [firstName, lastName].filter(Boolean).join(" ") || email?.split("@")[0];

  const user = await prisma.user.upsert({
    where: { clerkId },
    create: {
      clerkId,
      email: email ?? `${clerkId}@placeholder.local`,
      label,
    },
    update: {
      email: email ?? undefined,
      label,
    },
  });

  // Users created via Clerk's dashboard never hit the JWT first-login path,
  // so claim their pending invites here too. Wallet provisioning stays on
  // the request paths (resolveClerkOperator, /auth/me) so a Circle outage
  // can never fail webhook delivery. Best-effort: never throw.
  if (email) {
    try {
      await claimPendingInvites(user.id, normalizeEmail(email));
    } catch {
      // ignore — /auth/me and the invite-accept endpoint retry
    }
  }
}

async function handleUserDeleted(event: ClerkWebhookEvent) {
  const clerkId = event.data.id as string;
  if (!clerkId) return;

  // Delete user and cascade memberships
  await prisma.user.deleteMany({ where: { clerkId } });
}

async function handleOrganizationEvent(event: ClerkWebhookEvent) {
  const data = event.data;
  const clerkId = data.id as string;
  if (!clerkId) return;

  const name = data.name as string;
  const slug = data.slug as string | undefined;

  await prisma.organization.upsert({
    where: { clerkId },
    create: {
      clerkId,
      name,
      slug: slug ?? name.toLowerCase().replace(/[^a-z0-9]+/g, "-"),
    },
    update: {
      name,
      slug: slug ?? undefined,
    },
  });
}

async function handleOrganizationDeleted(event: ClerkWebhookEvent) {
  const clerkId = event.data.id as string;
  if (!clerkId) return;

  // Delete org and cascade memberships
  await prisma.organization.deleteMany({ where: { clerkId } });
}

async function handleMembershipEvent(event: ClerkWebhookEvent) {
  const data = event.data;
  const orgData = data.organization as Record<string, unknown> | undefined;
  const userData = data.user as Record<string, unknown> | undefined;
  const orgClerkId = orgData?.id as string | undefined;
  const userClerkId = userData?.id as string | undefined;
  const role = data.role as string | undefined;

  if (!orgClerkId || !userClerkId || !role) return;

  // Find local org and user by clerkId
  const org = await prisma.organization.findUnique({ where: { clerkId: orgClerkId } });
  const user = await prisma.user.findUnique({ where: { clerkId: userClerkId } });

  if (!org || !user) return;

  await prisma.membership.upsert({
    where: {
      userId_organizationId: {
        userId: user.id,
        organizationId: org.id,
      },
    },
    create: {
      userId: user.id,
      organizationId: org.id,
      role,
    },
    update: {
      role,
    },
  });
}

async function handleMembershipDeleted(event: ClerkWebhookEvent) {
  const data = event.data;
  const orgData = data.organization as Record<string, unknown> | undefined;
  const userData = data.user as Record<string, unknown> | undefined;
  const orgClerkId = orgData?.id as string | undefined;
  const userClerkId = userData?.id as string | undefined;

  if (!orgClerkId || !userClerkId) return;

  const org = await prisma.organization.findUnique({ where: { clerkId: orgClerkId } });
  const user = await prisma.user.findUnique({ where: { clerkId: userClerkId } });

  if (!org || !user) return;

  await prisma.membership.deleteMany({
    where: {
      userId: user.id,
      organizationId: org.id,
    },
  });
}
