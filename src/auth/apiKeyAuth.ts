import type { FastifyReply, FastifyRequest } from "fastify";
import { findCredential } from "./credentials.js";
import { verifyRequestSignature, type SignatureFailure } from "./requestSignature.js";
import { recordAuthFailure } from "./failureAlert.js";
import { generateCorrelationId, runWithCorrelation } from "./correlation.js";
import { verifySessionToken } from "./jwt.js";

/// Auth middleware for the admin/approver write routes.
///
/// Supports two auth methods:
///   1. API key: `x-api-key` header → findCredential (existing)
///   2. JWT: `Authorization: Bearer <token>` → verifySessionToken (new)
///
/// Both set `req.operator` so downstream handlers can attribute actions
/// to a specific person. JWT auth is for humans (Google OAuth), API key
/// auth is for programs/agents.

function reject(req: FastifyRequest, reply: FastifyReply, code: number, error: string, failure?: { role: string; reason: string }) {
  if (failure) recordAuthFailure(req.ip, failure);
  return reply.code(code).send({ error });
}

function signatureRejection(req: FastifyRequest, reply: FastifyReply, role: string, failure: SignatureFailure) {
  if (failure.ok) return;
  req.log.warn({ role, reason: failure.reason, ip: req.ip }, "rejected signed request");
  return reject(req, reply, 401, `invalid request signature (${failure.reason})`, { role, reason: failure.reason });
}

/// Extract the API key from the Authorization header or x-api-key header.
function extractApiKey(req: FastifyRequest): string | undefined {
  // Check Authorization: Bearer <token> first (JWT or API key)
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith("Bearer ")) {
    const token = authHeader.slice(7);
    // If it looks like a JWT (has 3 dot-separated base64url parts),
    // try JWT verification first.
    if (token.split(".").length === 3) {
      const jwt = verifySessionToken(token);
      if (jwt) {
        // JWT is valid — return a special marker so the caller knows
        // this is a JWT-authenticated user, not an API key.
        return `__jwt:${jwt.sub}:${jwt.email}:${jwt.role}:${jwt.walletAddress ?? ""}:${jwt.isProductionAccess}`;
      }
    }
    // Not a valid JWT — fall through to treat it as an API key
    return token;
  }

  // Check x-api-key header
  const apiKey = req.headers["x-api-key"];
  if (typeof apiKey === "string" && apiKey.length > 0) {
    return apiKey;
  }

  return undefined;
}

/// Fastify preHandler factory. Use as:
///   app.post("/policies", { preHandler: requireRole("admin") }, handler)
export function requireRole(role: "admin" | "approver") {
  return async function requireRoleHandler(req: FastifyRequest, reply: FastifyReply) {
    const correlationId = generateCorrelationId();
    req.correlationId = correlationId;

    const provided = extractApiKey(req);

    if (typeof provided !== "string" || provided.length === 0) {
      req.log.warn({ role, ip: req.ip }, "rejected request with missing auth");
      return reject(req, reply, 401, `missing authentication (requires ${role} credentials)`, { role, reason: "missing_key" });
    }

    // ── JWT auth path ────────────────────────────────────────────────
    if (provided.startsWith("__jwt:")) {
      const [, jwtId, jwtEmail, jwtRole, , isProductionAccess] = provided.split(":");

      if (jwtRole !== role && jwtRole !== "admin") {
        // Admins can access approver routes; approvers cannot access admin routes.
        if (!(jwtRole === "admin" && role === "approver")) {
          req.log.warn({ role, jwtRole, ip: req.ip }, "rejected JWT with insufficient role");
          return reject(req, reply, 403, "insufficient permissions");
        }
      }

      req.operator = {
        id: jwtId,
        label: jwtEmail,
        role: role,
      };

      return; // JWT auth — skip API key and signature verification
    }

    // ── API key auth path ────────────────────────────────────────────
    //
    // Constant-time by construction: findCredential hashes the provided key
    // and compares fixed-length SHA-256 digests, so no per-credential loop
    // ever leaks how many credentials exist or where a near-miss diverges.
    const operator = findCredential(role, provided);
    if (!operator) {
      req.log.warn({ role, ip: req.ip }, "rejected request with invalid api key");
      return reject(req, reply, 401, "invalid api key", { role, reason: "invalid_key" });
    }

    req.operator = operator;

    // Signed-request verification needs the raw provided key as the HMAC
    // key, so it happens here rather than on a route-level hook.
    const signature = verifyRequestSignature(
      provided,
      {
        timestamp: req.headers["x-timestamp"],
        nonce: req.headers["x-nonce"],
        signature: req.headers["x-signature"],
      },
      req.body,
    );
    return signatureRejection(req, reply, role, signature);
  };
}
