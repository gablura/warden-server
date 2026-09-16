import type { FastifyReply, FastifyRequest } from "fastify";
import crypto from "node:crypto";
import { config } from "../config.js";
import { prisma } from "../db/client.js";
import { findCredential } from "./credentials.js";
import { verifyScopedToken, type ScopedTokenClaims } from "./jwt.js";
import { ensureUserWallet } from "./wallet.js";
import { claimPendingInvites } from "./invites.js";
import { unsignedRequestsAllowed, verifyRequestSignature, type SignatureFailure } from "./requestSignature.js";
import { recordAuthFailure } from "./failureAlert.js";
import { generateCorrelationId } from "./correlation.js";

// ── JWKS cache ────────────────────────────────────────────────────────
// Clerk publishes its signing keys at a JWKS endpoint. We cache them
// and refresh every 10 minutes to avoid a network call on every request.

interface JwksKey {
  kid: string;
  kty: string;
  n: string;
  e: string;
  alg: string;
  use: string;
}

let jwksCache: { keys: JwksKey[]; fetchedAt: number } | null = null;
const JWKS_CACHE_TTL_MS = 10 * 60 * 1000;

async function getJwks(): Promise<JwksKey[]> {
  if (jwksCache && Date.now() - jwksCache.fetchedAt < JWKS_CACHE_TTL_MS) {
    return jwksCache.keys;
  }

  const res = await fetch("https://api.clerk.com/v1/jwks", {
    headers: { Authorization: `Bearer ${config.CLERK_SECRET_KEY}` },
  });

  if (!res.ok) throw new Error(`Failed to fetch JWKS: ${res.status}`);
  const data = await res.json() as { keys: JwksKey[] };
  jwksCache = { keys: data.keys, fetchedAt: Date.now() };
  return data.keys;
}

// ── JWT verification ──────────────────────────────────────────────────
// Minimal RS256 verification against Clerk's JWKS. Only verifies the
// signature and expiry — audience/issuer checks are secondary since
// the JWKS itself is already scoped to our Clerk instance.

function base64urlDecode(str: string): Buffer {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(padded, "base64");
}

interface ClerkJwtPayload {
  sub: string;
  sid?: string;
  org_id?: string;
  org_role?: string;
  email?: string;
  exp: number;
  iat: number;
}

async function verifyClerkJwt(token: string): Promise<ClerkJwtPayload | null> {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;

    const [headerB64, bodyB64, sigB64] = parts;
    const header = JSON.parse(base64urlDecode(headerB64).toString()) as { kid: string; alg: string };
    const body = JSON.parse(base64urlDecode(bodyB64).toString()) as ClerkJwtPayload;

    // Check expiry
    if (body.exp < Math.floor(Date.now() / 1000)) return null;

    // Check algorithm
    if (header.alg !== "RS256") return null;

    // Find the key in JWKS
    const keys = await getJwks();
    const key = keys.find((k) => k.kid === header.kid);
    if (!key) return null;

    // Verify signature using Node's crypto
    const publicKey = crypto.createPublicKey({
      key: { kty: key.kty, n: key.n, e: key.e, alg: "RS256" },
      format: "jwk",
    });

    const verifier = crypto.createVerify("RSA-SHA256");
    verifier.update(`${headerB64}.${bodyB64}`);

    const sigBuffer = base64urlDecode(sigB64);
    const valid = verifier.verify(publicKey, sigBuffer);

    return valid ? body : null;
  } catch {
    return null;
  }
}

// ── Operator type ─────────────────────────────────────────────────────

export interface Operator {
  id: string;
  label: string;
  role: string;
  orgId?: string;
  orgRole?: string;
  walletAddress?: string;
  maxApproval?: bigint;
}

// ── Helpers ───────────────────────────────────────────────────────────

function reject(req: FastifyRequest, reply: FastifyReply, code: number, error: string, failure?: { role: string; reason: string }) {
  if (failure) recordAuthFailure(req.ip, failure);
  return reply.code(code).send({ error });
}

function signatureRejection(req: FastifyRequest, reply: FastifyReply, role: string, failure: SignatureFailure) {
  if (failure.ok) return;
  req.log.warn({ role, reason: failure.reason, ip: req.ip }, "rejected signed request");
  // `unsigned_request` gets its own message: nothing is "invalid" about the
  // signature — there isn't one, and the fix is to start signing, not to
  // debug an HMAC. scripts/signed-request-example.mjs shows how.
  const message =
    failure.reason === "unsigned_request"
      ? "request signing is required for api-key auth (send x-timestamp, x-nonce, and x-signature — see scripts/signed-request-example.mjs)"
      : `invalid request signature (${failure.reason})`;
  return reject(req, reply, 401, message, { role, reason: failure.reason });
}

// ── Extract auth from request ─────────────────────────────────────────

type AuthResult =
  | { kind: "clerk"; userId: string; sessionId?: string; orgId?: string; orgRole?: string }
  | { kind: "scoped"; claims: ScopedTokenClaims }
  | { kind: "api_key"; operator: Operator }
  | { kind: "none" };

async function extractAuth(req: FastifyRequest): Promise<AuthResult> {
  const authHeader = req.headers.authorization;

  // ── Bearer token: Clerk JWT, scoped session token, or API key ──────
  if (authHeader?.startsWith("Bearer ")) {
    const token = authHeader.slice(7);

    if (token.split(".").length === 3) {
      // Try Clerk JWT verification
      if (config.CLERK_SECRET_KEY) {
        const payload = await verifyClerkJwt(token);
        if (payload) {
          return {
            kind: "clerk",
            userId: payload.sub,
            sessionId: payload.sid,
            orgId: payload.org_id,
            orgRole: payload.org_role,
          };
        }
      }

      // Try short-lived org-scoped token (POST /auth/token, §6). Checked
      // after Clerk so a Clerk session can never be mistaken for a scope.
      const scoped = verifyScopedToken(token);
      if (scoped) {
        return { kind: "scoped", claims: scoped };
      }
    }

    // Try API key (service callers without Clerk accounts)
    if (token.length >= 32) {
      const adminMatch = findCredential("admin", token);
      if (adminMatch) return { kind: "api_key", operator: adminMatch };
      const approverMatch = findCredential("approver", token);
      if (approverMatch) return { kind: "api_key", operator: approverMatch };
    }

    return { kind: "none" };
  }

  // ── x-api-key header ───────────────────────────────────────────────
  const apiKey = req.headers["x-api-key"];
  if (typeof apiKey === "string" && apiKey.length > 0) {
    const adminMatch = findCredential("admin", apiKey);
    if (adminMatch) return { kind: "api_key", operator: adminMatch };
    const approverMatch = findCredential("approver", apiKey);
    if (approverMatch) return { kind: "api_key", operator: approverMatch };
    return { kind: "none" };
  }

  return { kind: "none" };
}

// ── Resolve Clerk user → Operator ─────────────────────────────────────

async function resolveClerkOperator(
  userId: string,
  requestedRole: "admin" | "approver",
  orgId?: string,
): Promise<Operator | null> {
  // Find or create user in our DB
  let user = await prisma.user.findUnique({ where: { clerkId: userId } });

  if (!user) {
    // Fetch from Clerk API
    const res = await fetch(`https://api.clerk.com/v1/users/${userId}`, {
      headers: { Authorization: `Bearer ${config.CLERK_SECRET_KEY}` },
    });
    if (!res.ok) return null;

    const clerkUser = await res.json() as {
      id: string;
      email_addresses: Array<{ email_address: string; id: string }>;
      primary_email_address_id: string;
    };

    const email = clerkUser.email_addresses.find((e) => e.id === clerkUser.primary_email_address_id)?.email_address;
    if (!email) return null;

    user = await prisma.user.create({
      data: {
        clerkId: userId,
        email,
        label: email.split("@")[0],
      },
    });

    // First login: attach any pending invites for this email (join-via-link
    // works even when the invite was sent before the account existed), then
    // provision the embedded wallet. Both are best-effort and must never
    // fail authentication — the next request retries.
    try {
      await claimPendingInvites(user.id, user.email);
    } catch {
      // ignore — /auth/me and the invite-accept endpoint retry
    }
  }

  // Lazy wallet provisioning: only fires while the record has no wallet,
  // so the hot path stays a pure DB read once provisioned. A Circle outage
  // is swallowed here — the next request retries.
  if (!user.walletAddress || !user.walletId) {
    try {
      const wallet = await ensureUserWallet(user.id);
      if (wallet) {
        user = { ...user, walletId: wallet.walletId, walletAddress: wallet.address };
      }
    } catch {
      // ignore — retry on the next request
    }
  }

  // If orgId provided, resolve membership role
  if (orgId) {
    const membership = await prisma.membership.findUnique({
      where: { userId_organizationId: { userId: user.id, organizationId: orgId } },
    });

    if (!membership) return null;

    return {
      id: user.id,
      label: user.label ?? user.email,
      role: membership.role,
      orgId,
      orgRole: membership.role,
      walletAddress: user.walletAddress ?? undefined,
    };
  }

  // No org specified — return user with their highest role across orgs
  const memberships = await prisma.membership.findMany({
    where: { userId: user.id },
    orderBy: { role: "asc" },
  });

  const highestMembership = memberships[0];

  return {
    id: user.id,
    label: user.label ?? user.email,
    role: highestMembership?.role ?? "viewer",
    orgId: highestMembership?.organizationId,
    orgRole: highestMembership?.role,
    walletAddress: user.walletAddress ?? undefined,
  };
}

// ── requireRole middleware ─────────────────────────────────────────────
//
// Supports four auth methods:
//   1. Scoped session token (§6): short-lived, bound to (user, org, role).
//      Identity + role come straight from verified claims.
//   2. Clerk session JWT: identifies user, resolves org membership live.
//   3. API key: x-api-key header or Bearer → findCredential. Service
//      callers only — humans use 1 or 2.
//   4. None: rejected
//
// The `orgId` query parameter scopes Clerk-JWT callers to a specific org
// (falling back to the highest role across orgs when absent). Scoped
// tokens are already org-bound: a request naming a *different* orgId is
// rejected rather than re-scoped.

export function requireRole(role: "admin" | "approver" | "viewer") {
  return async function requireRoleHandler(req: FastifyRequest, reply: FastifyReply) {
    const correlationId = generateCorrelationId();
    req.correlationId = correlationId;

    const auth = await extractAuth(req);

    // ── Scoped token path (§6) ────────────────────────────────────────
    if (auth.kind === "scoped") {
      const { claims } = auth;
      const requestedOrgId = (req.query as Record<string, string>)?.orgId as string | undefined;
      if (requestedOrgId !== undefined && requestedOrgId !== claims.orgId) {
        req.log.warn({ role, ip: req.ip }, "rejected scoped token used for a different org");
        return reject(req, reply, 403, "token is scoped to a different organization");
      }

      // Check role hierarchy: owner > admin > approver > viewer
      const hierarchy = ["owner", "admin", "approver", "viewer"];
      const userLevel = hierarchy.indexOf(claims.role);
      const requiredLevel = hierarchy.indexOf(role);

      // Unknown roles fail closed (indexOf -1 would otherwise outrank owner).
      if (userLevel < 0 || userLevel > requiredLevel) {
        req.log.warn({ role, tokenRole: claims.role, ip: req.ip }, "rejected: insufficient token role");
        return reject(req, reply, 403, "insufficient permissions");
      }

      req.operator = {
        id: claims.sub,
        label: claims.email,
        role: claims.role,
        orgId: claims.orgId,
        orgRole: claims.role,
        walletAddress: claims.walletAddress,
      };
      return;
    }

    // ── Clerk auth path ──────────────────────────────────────────────
    if (auth.kind === "clerk") {
      const orgId = (req.query as Record<string, string>)?.orgId as string | undefined;
      const operator = await resolveClerkOperator(auth.userId, role as "admin" | "approver", orgId);
      if (!operator) {
        return reject(req, reply, 401, "user not found or not a member of this organization");
      }

      // Check role hierarchy: owner > admin > approver > viewer.
      // Unknown role strings fail closed: indexOf returns -1, which would
      // otherwise sort above owner and grant everything.
      const hierarchy = ["owner", "admin", "approver", "viewer"];
      const userLevel = hierarchy.indexOf(operator.orgRole ?? "viewer");
      const requiredLevel = hierarchy.indexOf(role);

      if (userLevel < 0 || userLevel > requiredLevel) {
        req.log.warn({ role, orgRole: operator.orgRole, ip: req.ip }, "rejected: insufficient org role");
        return reject(req, reply, 403, "insufficient permissions");
      }

      req.operator = operator;
      return;
    }

    // ── API key auth path ────────────────────────────────────────────
    if (auth.kind === "api_key") {
      const { operator } = auth;

      // API key role check: owner > admin > approver > viewer
      const hierarchy = ["admin", "approver"];
      const userLevel = hierarchy.indexOf(operator.role as "admin" | "approver");
      const requiredLevel = hierarchy.indexOf(role as "admin" | "approver");

      if (requiredLevel >= 0 && (userLevel < 0 || userLevel > requiredLevel)) {
        req.log.warn({ role, operatorRole: operator.role, ip: req.ip }, "rejected: insufficient api key role");
        return reject(req, reply, 403, "insufficient permissions");
      }

      req.operator = operator;

      // API key signed-request verification. Signing is optional while the
      // configured migration window is open (see requestSignature.ts); once
      // REQUIRE_SIGNED_REQUESTS=true or the deadline passes, unsigned
      // api-key requests are rejected with `unsigned_request`.
      const apiKey = req.headers["x-api-key"] ?? req.headers.authorization?.slice(7);
      if (typeof apiKey === "string") {
        const signature = verifyRequestSignature(
          apiKey,
          {
            timestamp: req.headers["x-timestamp"],
            nonce: req.headers["x-nonce"],
            signature: req.headers["x-signature"],
          },
          req.body,
          { allowUnsigned: unsignedRequestsAllowed() },
        );
        return signatureRejection(req, reply, role, signature);
      }
      return;
    }

    // ── No auth ──────────────────────────────────────────────────────
    req.log.warn({ role, ip: req.ip }, "rejected request with missing auth");
    return reject(req, reply, 401, `missing authentication (requires ${role} credentials)`, { role, reason: "missing_key" });
  };
}

// ── Export for routes ──────────────────────────────────────────────────
export { config as appConfig };
