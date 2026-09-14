import type { FastifyInstance } from "fastify";
import { prisma, serializeBigInts } from "../db/client.js";

export async function agentRoutes(app: FastifyInstance) {
  app.get("/agents", async () => {
    const agents = await prisma.agent.findMany({ orderBy: { spentToday: "desc" } });
    return serializeBigInts(agents);
  });

  app.get<{ Params: { address: string } }>("/agents/:address", async (req, reply) => {
    const agent = await prisma.agent.findUnique({ where: { address: req.params.address } });
    if (!agent) return reply.code(404).send({ error: "agent not found" });

    const recentPayments = await prisma.event.findMany({
      where: { agent: req.params.address },
      orderBy: { timestamp: "desc" },
      take: 50,
    });

    return serializeBigInts({ agent, recentPayments });
  });
}