import crypto from "node:crypto";
import { config } from "../config.js";

// Scoped session tokens — the §6 exchange product.
//
// Flow: the frontend holds a Clerk session, calls POST /auth/token with an
// orgId, and gets back a short-lived token bound to (user, org, role,
// wallet). Write routes accept it as `Authorization: Bearer <token>` and
// authorize straight from its claims — no shared static secret, no
// per-request membership lookup.
//
// Properties:
// - HS256 with JWT_SECRET (required at boot, see config.ts). Short 15-min
//   expiry bounds role staleness: a demotion takes effect at most 15 minutes
//   late for token holders; Clerk-JWT callers re-resolve every request.
// - `scope: "warden-org"` distinguishes these from any other JWT-shaped
//   credential (Clerk session tokens, API keys are never dot-shaped... but
//   a raw 64-hex API key has no dots, so the 3-part shape alone already
//   separates them; the scope claim is defense in depth).
// - Minimal implementation on Node's built-in crypto, matching the file's
//   original convention (no jsonwebtoken/jose dependency).

const ALG = "HS256";
const SCOPE = "warden-org";
const EXPIRY_SECONDS = 15 * 60; // 15 minutes

export interface ScopedTokenClaims {
  sub: string;
  email: string;
  orgId: string;
  role: string;
  walletAddress?: string;
  scope: typeof SCOPE;
  iat: number;
  exp: number;
}

function base64url(data: Buffer | string): string {
  return (Buffer.isBuffer(data) ? data : Buffer.from(data))
    .toString("base64url");
}

function sign(header: Record<string, unknown>, payload: Record<string, unknown>, secret: string): string {
  const headerB64 = base64url(JSON.stringify(header));
  const bodyB64 = base64url(JSON.stringify(payload));
  const signature = crypto
    .createHmac("sha256", secret)
    .update(`${headerB64}.${bodyB64}`)
    .digest();
  return `${headerB64}.${bodyB64}.${base64url(signature)}`;
}

export function createScopedToken(user: {
  id: string;
  email: string;
  orgId: string;
  role: string;
  walletAddress?: string | null;
}): { token: string; expiresAt: Date } {
  const now = Math.floor(Date.now() / 1000);
  const token = sign(
    { alg: ALG, typ: "JWT" },
    {
      sub: user.id,
      email: user.email,
      orgId: user.orgId,
      role: user.role,
      walletAddress: user.walletAddress ?? undefined,
      scope: SCOPE,
      iat: now,
      exp: now + EXPIRY_SECONDS,
    },
    config.JWT_SECRET!,
  );
  return { token, expiresAt: new Date((now + EXPIRY_SECONDS) * 1000) };
}

export function verifyScopedToken(token: string): ScopedTokenClaims | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;

    const [headerB64, bodyB64, sigB64] = parts;

    const header: { alg?: string } = JSON.parse(Buffer.from(headerB64, "base64url").toString());
    if (header.alg !== ALG) return null;

    // Verify signature
    const expected = crypto
      .createHmac("sha256", config.JWT_SECRET!)
      .update(`${headerB64}.${bodyB64}`)
      .digest()
      .toString("base64url");

    if (!crypto.timingSafeEqual(Buffer.from(sigB64), Buffer.from(expected))) {
      return null;
    }

    const payload = JSON.parse(Buffer.from(bodyB64, "base64url").toString()) as ScopedTokenClaims;

    if (payload.scope !== SCOPE) return null;
    if (typeof payload.sub !== "string" || typeof payload.orgId !== "string" || typeof payload.role !== "string") {
      return null;
    }
    if (payload.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}
