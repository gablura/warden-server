import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { isAddress } from "viem";
import { policyRegistry } from "../chain/client.js";
import { serializeTx } from "../chain/txQueue.js";
import { prisma } from "../db/client.js";
import { requireRole } from "../auth/clerkAuth.js";
import { getCorrelationId } from "../auth/correlation.js";

const addressField = z.string().refine((v) => isAddress(v), "invalid EVM address");

const setPolicyBody = z.object({
  agent: addressField,
  dailyCap: z.coerce.bigint(),
  perTxCap: z.coerce.bigint(),
  escalationThreshold: z.coerce.bigint(),
}).strict();

const setAllowlistBody = z.object({
  agent: addressField,
  counterparty: addressField,
  allowed: z.boolean(),
}).strict();

// Both routes require the admin role (see auth/clerkAuth.ts) and
// are rate-limited independently of the server-wide default, since
// each successful call sends a real transaction and costs real gas.
const gasSpendingRoute = {
  preHandler: requireRole("admin"),
  config: { rateLimit: { max: 20, timeWindow: "1 minute" } },
};

// Server-side attribution for admin policy changes, matching approvals.ts:
// the on-chain AuditLog can't name the credential that requested the
// change, so the operator_actions table records it, tied to the tx hash.
async function recordOperatorAction(
  operator: { id: string; label: string; role: string },
  action: string,
  subjectId: string,
  txHash: string,
) {
  await prisma.operatorAction.create({
    data: {
      operatorId: operator.id,
      operatorLabel: operator.label,
      role: operator.role,
      action,
      subjectId,
      txHash,
      correlationId: getCorrelationId() ?? null,
    },
  });
}

export async function policyRoutes(app: FastifyInstance) {
  app.post("/policies", gasSpendingRoute, async (req, reply) => {
    if (!req.operator) return reply.code(500).send({ error: "internal_error", message: "operator identity missing" });
    const body = setPolicyBody.parse(req.body);
    // Serialized per wallet (see txQueue.ts) so two concurrent admin calls
    // can't collide on the same nonce.
    const hash = await serializeTx("admin", () =>
      policyRegistry.admin.write.setPolicy([
        body.agent as `0x${string}`, body.dailyCap, body.perTxCap, body.escalationThreshold,
      ]),
    );
    await recordOperatorAction(req.operator, "set_policy", body.agent.toLowerCase(), hash);
    return reply.send({ txHash: hash, correlationId: req.correlationId });
  });

  app.post("/policies/allowlist", gasSpendingRoute, async (req, reply) => {
    if (!req.operator) return reply.code(500).send({ error: "internal_error", message: "operator identity missing" });
    const body = setAllowlistBody.parse(req.body);
    const hash = await serializeTx("admin", () =>
      policyRegistry.admin.write.setAllowlist([
        body.agent as `0x${string}`, body.counterparty as `0x${string}`, body.allowed,
      ]),
    );
    await recordOperatorAction(req.operator, "set_allowlist", `${body.agent.toLowerCase()}:${body.counterparty.toLowerCase()}`, hash);
    return reply.send({ txHash: hash, correlationId: req.correlationId });
  });
}