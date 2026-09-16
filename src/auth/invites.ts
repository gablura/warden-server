import crypto from "node:crypto";
import { prisma } from "../db/client.js";

// ── Token-based organization invitations ─────────────────────────────
//
// Invites are persisted rows (see Invitation in schema.prisma), not just
// Clerk emails, so joining works whether or not Clerk delivery is
// configured:
//
// - POST /auth/orgs/:orgId/invite creates (or refreshes) a row and returns
//   a token; the frontend builds the invite link from it.
// - POST /auth/invites/:token/accept consumes the token and creates the
//   Membership with the invited role (default `viewer`).
// - claimPendingInvites() runs on every first-login path and attaches any
//   matching pending invites automatically — clicking the link before the
//   invitee's first login still works.
//
// Accepting an invite creates a Membership and ONLY a Membership: it never
// touches chain state (no setApprover, no key grants). On-chain permissions
// are granted separately (see the two-source-of-truth design in §5).

export const INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
export const INVITE_ROLES = ["admin", "approver", "viewer"] as const;
export type InviteRole = (typeof INVITE_ROLES)[number];

/// Canonical email form for invite matching: trim + lowercase, so
/// "Alice@Example.com" matches an invite sent to "alice@example.com".
export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export function newInviteToken(): string {
  return crypto.randomBytes(32).toString("hex");
}

function isLive(invite: { expiresAt: Date; acceptedAt: Date | null }): boolean {
  return invite.acceptedAt === null && invite.expiresAt.getTime() > Date.now();
}

/// Attach every live invite matching the user's email as a Membership with
/// the invited role. Idempotent: already-a-member is a skip (the invite is
/// still marked accepted so it doesn't linger), and the whole batch is
/// best-effort — invite claiming must never fail a login.
export async function claimPendingInvites(userId: string, email: string): Promise<void> {
  const invites = await prisma.invitation.findMany({
    where: {
      email: normalizeEmail(email),
      acceptedAt: null,
      expiresAt: { gt: new Date() },
    },
  });

  for (const invite of invites) {
    if (!isLive(invite)) continue;
    try {
      const existing = await prisma.membership.findUnique({
        where: { userId_organizationId: { userId, organizationId: invite.organizationId } },
      });
      if (!existing) {
        await prisma.membership.create({
          data: { userId, organizationId: invite.organizationId, role: invite.role },
        });
      }
      await prisma.invitation.update({
        where: { id: invite.id },
        data: { acceptedAt: new Date() },
      });
    } catch {
      // Best-effort: a concurrent accept (P2002 on the membership) or a
      // deleted org just means someone else completed this invite first.
      continue;
    }
  }
}
