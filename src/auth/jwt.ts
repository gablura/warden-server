import crypto from "node:crypto";
import { config } from "../config.js";

// Minimal JWT implementation using Node's built-in crypto — avoids adding
// jsonwebtoken/jose as a dependency. The tokens are short-lived session
// credentials (7-day expiry), not long-lived identity documents, so
// HS256 is sufficient.

const ALG = "HS256";
const EXPIRY_SECONDS = 7 * 24 * 60 * 60; // 7 days

interface JwtPayload {
  sub: string;
  email: string;
  role: "admin" | "approver";
  walletAddress?: string;
  isProductionAccess: boolean;
  iat: number;
  exp: number;
}

function base64url(data: Buffer | string): string {
  return (Buffer.isBuffer(data) ? data : Buffer.from(data))
    .toString("base64url");
}

function sign(payload: Record<string, unknown>, secret: string): string {
  const header = base64url(JSON.stringify({ alg: ALG, typ: "JWT" }));
  const body = base64url(JSON.stringify(payload));
  const signature = crypto
    .createHmac("sha256", secret)
    .update(`${header}.${body}`)
    .digest();
  return `${header}.${body}.${base64url(signature)}`;
}

export function createSessionToken(user: {
  id: string;
  email: string;
  role: string;
  walletAddress?: string | null;
  isProductionAccess: boolean;
}): string {
  const now = Math.floor(Date.now() / 1000);
  return sign(
    {
      sub: user.id,
      email: user.email,
      role: user.role,
      walletAddress: user.walletAddress ?? undefined,
      isProductionAccess: user.isProductionAccess,
      iat: now,
      exp: now + EXPIRY_SECONDS,
    },
    config.JWT_SECRET!,
  );
}

export function verifySessionToken(token: string): JwtPayload | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;

    const [headerB64, bodyB64, sigB64] = parts;

    // Verify signature
    const expected = crypto
      .createHmac("sha256", config.JWT_SECRET!)
      .update(`${headerB64}.${bodyB64}`)
      .digest()
      .toString("base64url");

    if (!crypto.timingSafeEqual(Buffer.from(sigB64), Buffer.from(expected))) {
      return null;
    }

    const payload: JwtPayload = JSON.parse(Buffer.from(bodyB64, "base64url").toString());

    // Check expiry
    if (payload.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}
