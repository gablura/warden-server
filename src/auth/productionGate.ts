import type { FastifyReply, FastifyRequest } from "fastify";
import { prisma } from "../db/client.js";
import { config } from "../config.js";

/// Production/mainnet gate (§7): `verified` lives on the Organization.
///
/// - Testnet (`WARDEN_NETWORK=testnet`): open by design. New orgs explore
///   freely — no gate, per the "fast at the top" half of the spec.
/// - Mainnet (`WARDEN_NETWORK=mainnet`): every money-moving route requires
///   the caller's org to be verified. Unverified orgs get a 403 naming the
///   reason; verification itself is an explicit manual review step (direct
///   DB update), deliberately not a self-serve endpoint.
///
/// Service callers (API keys, no org context) bypass the org check — they
/// are provisioned infrastructure, not org members. Scoped-token and Clerk
/// callers always carry an orgId after requireRole, so they are gated.
///
/// Usage:
///   app.post("/policies", { preHandler: [requireRole("admin"), productionGate()] }, handler)
export function productionGate() {
  return async function productionGateHandler(req: FastifyRequest, reply: FastifyReply) {
    const operator = req.operator;
    if (!operator) return; // requireRole should have run first

    // Testnet is ungated — exploration from the moment an org is created.
    if (config.WARDEN_NETWORK !== "mainnet") return;

    // API key users (services/programs) bypass the gate — they're already
    // provisioned by an admin who has production access.
    if (!operator.orgId) return;

    // The gated org is the one being acted on, not necessarily the one the
    // caller authenticated in the context of: a path org (role/invite
    // routes) beats a query org (policy/approval routes), which beats the
    // operator's default org. Without this, an admin of a verified org
    // could act on an unverified org through the same credential.
    const query = req.query as Record<string, unknown>;
    const params = req.params as Record<string, unknown>;
    const queryOrgId = typeof query.orgId === "string" ? query.orgId : undefined;
    const paramOrgId = typeof params.orgId === "string" ? params.orgId : undefined;
    const targetOrgId = paramOrgId ?? queryOrgId ?? operator.orgId;

    const org = await prisma.organization.findUnique({ where: { id: targetOrgId } });
    if (!org) {
      return reply.code(401).send({ error: "org_not_found", message: "Organization not found" });
    }

    if (!org.verified) {
      req.log.warn({ orgId: org.id, orgName: org.name }, "blocked mainnet operation: org not verified");
      return reply.code(403).send({
        error: "verification_required",
        message: "This action requires a verified organization. Contact support to request verification.",
      });
    }
  };
}
