import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { policyRegistry } from "../chain/client.js";
import { requireRole } from "../auth/apiKeyAuth.js";

const setPolicyBody = z.object({
  agent: z.string().startsWith("0x"),
  dailyCap: z.coerce.bigint(),
  perTxCap: z.coerce.bigint(),
  escalationThreshold: z.coerce.bigint(),
});

const setAllowlistBody = z.object({
  agent: z.string().startsWith("0x"),
  counterparty: z.string().startsWith("0x"),
  allowed: z.boolean(),
});

// Both routes require the admin x-api-key (see auth/apiKeyAuth.ts) and
// are rate-limited independently of the server-wide default, since
// each successful call sends a real transaction and costs real gas.
const gasSpendingRoute = {
  preHandler: requireRole("admin"),
  config: { rateLimit: { max: 20, timeWindow: "1 minute" } },
};

export async function policyRoutes(app: FastifyInstance) {
  app.post("/policies", gasSpendingRoute, async (req, reply) => {
    const body = setPolicyBody.parse(req.body);
    const hash = await policyRegistry.admin.write.setPolicy([
      body.agent as `0x${string}`, body.dailyCap, body.perTxCap, body.escalationThreshold,
    ]);
    return reply.send({ txHash: hash });
  });

  app.post("/policies/allowlist", gasSpendingRoute, async (req, reply) => {
    const body = setAllowlistBody.parse(req.body);
    const hash = await policyRegistry.admin.write.setAllowlist([
      body.agent as `0x${string}`, body.counterparty as `0x${string}`, body.allowed,
    ]);
    return reply.send({ txHash: hash });
  });
}