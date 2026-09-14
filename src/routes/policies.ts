import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { policyRegistry } from "../chain/client.js";

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

// TODO: wrap these two routes with your own admin auth middleware —
// this file assumes that's already handled upstream (e.g. a session
// check or API key on the Fastify instance) before it ever runs.
export async function policyRoutes(app: FastifyInstance) {
  app.post("/policies", async (req, reply) => {
    const body = setPolicyBody.parse(req.body);
    const hash = await policyRegistry.admin.write.setPolicy([
      body.agent as `0x${string}`, body.dailyCap, body.perTxCap, body.escalationThreshold,
    ]);
    return reply.send({ txHash: hash });
  });

  app.post("/policies/allowlist", async (req, reply) => {
    const body = setAllowlistBody.parse(req.body);
    const hash = await policyRegistry.admin.write.setAllowlist([
      body.agent as `0x${string}`, body.counterparty as `0x${string}`, body.allowed,
    ]);
    return reply.send({ txHash: hash });
  });
}