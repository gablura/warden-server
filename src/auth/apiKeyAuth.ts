import type { FastifyReply, FastifyRequest } from "fastify";
import { findCredential } from "./credentials.js";
import { verifyRequestSignature, type SignatureFailure } from "./requestSignature.js";
import { recordAuthFailure } from "./failureAlert.js";

/// Auth middleware for the admin/approver write routes.
///
/// What a request has to pass, in order:
///   1. Credential match — the x-api-key must belong to a *named* credential
///      with the required role (see credentials.ts). On success the request
///      carries `req.operator`, so handlers can attribute the action to a
///      person rather than a role.
///   2. Request signature, when the client signs (requestSignature.ts). An
///      unsigned request is accepted during the client migration window.
///
/// Every rejection is counted by the burst detector (failureAlert.ts) before
/// the response goes out.

function reject(req: FastifyRequest, reply: FastifyReply, code: number, error: string, failure?: { role: string; reason: string }) {
  if (failure) recordAuthFailure(req.ip, failure);
  return reply.code(code).send({ error });
}

function signatureRejection(req: FastifyRequest, reply: FastifyReply, role: string, failure: SignatureFailure) {
  if (failure.ok) return;
  req.log.warn({ role, reason: failure.reason, ip: req.ip }, "rejected signed request");
  return reject(req, reply, 401, `invalid request signature (${failure.reason})`, { role, reason: failure.reason });
}

/// Fastify preHandler factory. Use as:
///   app.post("/policies", { preHandler: requireRole("admin") }, handler)
export function requireRole(role: "admin" | "approver") {
  return async function requireRoleHandler(req: FastifyRequest, reply: FastifyReply) {
    const provided = req.headers["x-api-key"];

    if (typeof provided !== "string" || provided.length === 0) {
      req.log.warn({ role, ip: req.ip }, "rejected request with missing api key");
      return reject(req, reply, 401, `missing x-api-key header (requires ${role} key)`, { role, reason: "missing_key" });
    }

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
