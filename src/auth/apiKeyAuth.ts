import crypto from "node:crypto";
import type { FastifyReply, FastifyRequest } from "fastify";
import { config } from "../config.js";

type Role = "admin" | "approver";

/// Hashed once at module load, not per request. Two things this buys:
///
/// 1. Performance — the expensive-ish part (reading the real secret out
///    of config) happens once at boot; every request just hashes the
///    ~40-byte header value it received, which is microseconds.
/// 2. Safety — comparing two fixed-length SHA-256 digests means
///    crypto.timingSafeEqual never has to reject on a length mismatch,
///    which would itself leak how long the real key is. Comparing raw
///    strings of different lengths is the actual footgun here.
const roleKeyHashes: Record<Role, Buffer> = {
  admin: crypto.createHash("sha256").update(config.ADMIN_API_KEY).digest(),
  approver: crypto.createHash("sha256").update(config.APPROVER_API_KEY).digest(),
};

/// Fastify preHandler factory. Use as:
///   app.post("/policies", { preHandler: requireRole("admin") }, handler)
export function requireRole(role: Role) {
  const expected = roleKeyHashes[role];

  return async function requireRoleHandler(req: FastifyRequest, reply: FastifyReply) {
    const provided = req.headers["x-api-key"];

    if (typeof provided !== "string" || provided.length === 0) {
      return reply.code(401).send({ error: `missing x-api-key header (requires ${role} key)` });
    }

    const providedHash = crypto.createHash("sha256").update(provided).digest();

    // Buffers are always equal length here (both SHA-256 digests), so
    // this never throws — timingSafeEqual only throws on length
    // mismatch, which pre-hashing has already ruled out.
    if (!crypto.timingSafeEqual(providedHash, expected)) {
      req.log.warn({ role, ip: req.ip }, "rejected request with invalid api key");
      return reply.code(401).send({ error: "invalid api key" });
    }
  };
}