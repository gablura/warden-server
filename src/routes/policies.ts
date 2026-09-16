import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { isAddress } from "viem";
import { submitAsAdmin } from "../chain/signing.js";
import { resolveDeploymentForAgent } from "../chain/orgContracts.js";
import { prisma } from "../db/client.js";
import { requireRole } from "../auth/clerkAuth.js";
import { productionGate } from "../auth/productionGate.js";
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

// Both routes require the admin role (see auth/clerkAuth.ts), pass the
// production gate (verified orgs on mainnet, open on testnet), and are
// rate-limited independently of the server-wide default, since each
// successful call sends a real transaction and costs real gas.
//
// setPolicy/setAllowlist are admin-only on-chain, so the tx always comes
// from the admin relayer on the AGENT's deployment (its org's contracts on
// mainnet, global otherwise) — per-person identity is carried by the scoped
// session + audit row. See signing.submitAsAdmin.
const gasSpendingRoute = {
  preHandler: [requireRole("admin"), productionGate()],
  config: { rateLimit: { max: 20, timeWindow: "1 minute" } },
};

// Server-side attribution for admin policy changes, matching approvals.ts:
// the on-chain AuditLog can't name the credential that requested the
// change, so the operator_actions table records it, tied to the tx hash.
async function recordOperatorAction(
  operator: { id: string; label: string; role: string; walletAddress?: string },
  action: string,
  subjectId: string,
  signing: { txHash: string; signer: string; via: string },
) {
  await prisma.operatorAction.create({
    data: {
      operatorId: operator.id,
      operatorLabel: operator.label,
      role: operator.role,
      action,
      subjectId,
      txHash: signing.txHash,
      correlationId: getCorrelationId() ?? null,
      walletAddress: operator.walletAddress ?? null,
      signerAddress: signing.signer,
      signingVia: signing.via,
    },
  });
}

export async function policyRoutes(app: FastifyInstance) {
  app.post("/policies", gasSpendingRoute, async (req, reply) => {
    if (!req.operator) return reply.code(500).send({ error: "internal_error", message: "operator identity missing" });
    const body = setPolicyBody.parse(req.body);
    const deployment = await resolveDeploymentForAgent(body.agent);
    const signing = await submitAsAdmin(deployment, "policyRegistry", "setPolicy", [
      body.agent as `0x${string}`, body.dailyCap, body.perTxCap, body.escalationThreshold,
    ]);
    await recordOperatorAction(req.operator, "set_policy", body.agent.toLowerCase(), signing);
    return reply.send({ txHash: signing.txHash, signer: signing.signer, via: signing.via, correlationId: req.correlationId });
  });

  app.post("/policies/allowlist", gasSpendingRoute, async (req, reply) => {
    if (!req.operator) return reply.code(500).send({ error: "internal_error", message: "operator identity missing" });
    const body = setAllowlistBody.parse(req.body);
    const deployment = await resolveDeploymentForAgent(body.agent);
    const signing = await submitAsAdmin(deployment, "policyRegistry", "setAllowlist", [
      body.agent as `0x${string}`, body.counterparty as `0x${string}`, body.allowed,
    ]);
    await recordOperatorAction(req.operator, "set_allowlist", `${body.agent.toLowerCase()}:${body.counterparty.toLowerCase()}`, signing);
    return reply.send({ txHash: signing.txHash, signer: signing.signer, via: signing.via, correlationId: req.correlationId });
  });
}
