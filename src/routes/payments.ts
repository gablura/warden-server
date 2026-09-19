import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { isAddress } from "viem";
import { prisma } from "../db/client.js";
import { readAgentPolicy } from "../chain/policyState.js";
import { submitAsAgent } from "../chain/signing.js";
import { resolveDeploymentForAgent } from "../chain/orgContracts.js";
import { optionalAuth } from "../auth/clerkAuth.js";
import type { SigningResult } from "../chain/signing.js";

const addressField = z.string().refine((v) => isAddress(v), "invalid EVM address");

const submitPaymentBody = z.object({
  agent: addressField,
  counterparty: addressField,
  amount: z.coerce.bigint(),
}).strict();

export async function paymentRoutes(app: FastifyInstance) {
  app.post<{ Body: { agent: string; counterparty: string; amount: bigint } }>(
    "/payments",
    { preHandler: optionalAuth() },
    async (req, reply) => {
      const body = submitPaymentBody.parse(req.body);

      const policy = await readAgentPolicy(body.agent);
      if (!policy.exists) {
        return reply.code(404).send({ error: "not_found", message: "Agent not found" });
      }

      const deployment = await resolveDeploymentForAgent(body.agent);

      const checkResult = await deployment.publicClient.readContract({
        address: deployment.policyRegistry,
        abi: [
          {
            name: "checkPolicy",
            type: "function",
            inputs: [
              { name: "agent", type: "address" },
              { name: "counterparty", type: "address" },
              { name: "amount", type: "uint256" },
            ],
            outputs: [
              { name: "allowed", type: "bool" },
              { name: "needsApproval", type: "bool" },
              { name: "reason", type: "string" },
            ],
            stateMutability: "view",
          },
        ],
        functionName: "checkPolicy",
        args: [body.agent as `0x${string}`, body.counterparty as `0x${string}`, body.amount],
      });

      const [allowed, needsApproval, reason] = checkResult;

      if (!allowed) {
        await prisma.event.create({
          data: {
            agent: body.agent,
            counterparty: body.counterparty,
            amount: body.amount,
            decision: `blocked: ${reason}`,
            txHash: "",
          },
        });
        return reply.send({
          requestId: "0",
          status: "blocked",
          reason,
        });
      }

      const submitAsAgentPayment = async (): Promise<SigningResult> => {
        return submitAsAgent({
          agentAddress: body.agent,
          deployment,
          functionName: "requestPayment",
          functionSignature: "requestPayment(address,address,uint256)",
          requestArgs: [body.agent as `0x${string}`, body.counterparty as `0x${string}`, body.amount],
          ensureUnresolved: async () => {},
        });
      };

      if (needsApproval) {
        const signing = await submitAsAgentPayment();

        // Extract the on-chain requestId from the PaymentEscalated event
        const receipt = await deployment.publicClient.getTransactionReceipt({
          hash: signing.txHash as `0x${string}`,
        });
        const sgAddr = deployment.spendGuard.toLowerCase();
        let onChainRequestId = 0n;
        if (receipt) {
          for (const log of receipt.logs) {
            if (log.address.toLowerCase() !== sgAddr) continue;
            if (log.topics.length < 2) continue;
            // topics[1] = requestId (indexed uint256, left-padded to 32 bytes)
            try {
              const topic = log.topics[1];
              if (!topic) continue;
              const rid = BigInt(topic);
              if (rid > 0n) { onChainRequestId = rid; break; }
            } catch {}
          }
        }

        await prisma.pendingRequest.create({
          data: {
            deploymentKey: deployment.orgId ?? "global",
            requestId: onChainRequestId,
            agent: body.agent.toLowerCase(),
            counterparty: body.counterparty.toLowerCase(),
            amount: body.amount,
            resolved: false,
          },
        });

        return reply.send({
          requestId: onChainRequestId.toString(),
          status: "escalated",
        });
      }

      const signing = await submitAsAgentPayment();

      return reply.send({
        requestId: "0",
        status: "approved",
      });
    },
  );
}