import crypto from "node:crypto";
import { config } from "../config.js";

/// Short-lived WebSocket tickets — the auth primitive for /ws in multi-
/// tenant mode (hardening review §1 follow-up: the /ws hub had no identity,
/// so a wildcard subscriber could read every org's feed).
///
/// Flow: an authenticated client calls POST /auth/ws-ticket (any role —
/// same gate as /auth/token) and receives a ticket bound to the deployment
/// scope its REST calls already see (global, or its org's mainnet
/// deployment — resolved server-side, never client-chosen). The ticket is
/// appended to the upgrade URL (`/ws?ticket=...`) and verified once at
/// handshake; after that the connection carries its scope for life.
///
/// Properties:
/// - HMAC-SHA256 with JWT_SECRET — the same secret that backs scoped
///   session tokens (auth/jwt.ts), so no new key material to protect.
/// - 60-second TTL: long enough to hand to the upgrade request, short
///   enough that a leaked ticket is worthless. Tickets are NOT one-time —
///   replay within the TTL grants only the same read-only feed the
///   legitimate holder has; single-use state is not worth the bookkeeping.
/// - Payload carries (operatorId, orgId, iat, exp). The *scope* the
///   connection gets is derived from orgId: null → global, org id → that
///   org's resolved deployment. Resolution happens at issuance, so the
///   ticket can never name a deployment its holder isn't entitled to.

const TICKET_TTL_MS = 60_000;

export interface WsTicketClaims {
  v: 1;
  operatorId: string;
  /// Null = global scope. An org id = that org's resolved deployment.
  orgId: string | null;
  iat: number;
  exp: number;
}

export interface WsTicket {
  ticket: string;
  expiresAt: Date;
}

export function issueWsTicket(input: { operatorId: string; orgId: string | null }): WsTicket {
  const now = Date.now();
  const claims: WsTicketClaims = {
    v: 1,
    operatorId: input.operatorId,
    orgId: input.orgId,
    iat: now,
    exp: now + TICKET_TTL_MS,
  };
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const signature = crypto.createHmac("sha256", config.JWT_SECRET!).update(payload).digest("base64url");
  return { ticket: `${payload}.${signature}`, expiresAt: new Date(claims.exp) };
}

/// Returns the ticket's claims when the signature verifies and the ticket
/// is unexpired, null otherwise (malformed, wrong key, stale). The scope
/// decision itself lives with the caller — this only establishes that the
/// claims were minted by this server.
export function verifyWsTicket(ticket: string): { operatorId: string; orgId: string | null } | null {
  try {
    const parts = ticket.split(".");
    // Exactly two segments: anything else (trailing junk, extra dots) is not
    // a ticket this server minted.
    if (parts.length !== 2) return null;
    const [payload, signature] = parts;

    const expected = crypto.createHmac("sha256", config.JWT_SECRET!).update(payload).digest();
    const given = Buffer.from(signature, "base64url");
    // Length check first: timingSafeEqual throws on mismatched lengths.
    if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return null;

    const claims = JSON.parse(Buffer.from(payload, "base64url").toString()) as WsTicketClaims;
    if (claims.v !== 1) return null;
    if (typeof claims.operatorId !== "string" || claims.operatorId.length === 0) return null;
    if (claims.orgId !== null && typeof claims.orgId !== "string") return null;
    if (typeof claims.exp !== "number" || claims.exp < Date.now()) return null;

    return { operatorId: claims.operatorId, orgId: claims.orgId };
  } catch {
    return null;
  }
}
