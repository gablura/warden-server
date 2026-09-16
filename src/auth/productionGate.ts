import type { FastifyReply, FastifyRequest } from "fastify";
import { prisma } from "../db/client.js";

/// Middleware that blocks non-sandbox operations for organizations
/// that haven't been verified. Use on routes that interact with real
/// money (live agents, mainnet transactions, real approvals).
///
/// Sandbox routes (UI exploration, test policies, demo data) are
/// not gated — new orgs can explore freely.
///
/// Usage:
///   app.post("/agents", { preHandler: [requireRole("admin"), productionGate()] }, handler)
export function productionGate() {
  return async function productionGateHandler(req: FastifyRequest, reply: FastifyReply) {
    const operator = req.operator;
    if (!operator) return; // requireRole should have run first

    // API key users (agents/programs) bypass the gate — they're already
    // provisioned by an admin who has production access.
    if (!operator.orgId) return;

    const org = await prisma.organization.findUnique({ where: { id: operator.orgId } });
    if (!org) {
      return reply.code(401).send({ error: "org_not_found", message: "Organization not found" });
    }

    if (!org.verified) {
      req.log.warn({ orgId: org.id, orgName: org.name }, "blocked non-sandbox operation: org not verified");
      return reply.code(403).send({
        error: "verification_required",
        message: "This action requires a verified organization. Contact support to request verification.",
      });
    }
  };
}
