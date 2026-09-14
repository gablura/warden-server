import type { FastifyInstance } from "fastify";
import { prisma, serializeBigInts } from "../db/client.js";

export async function auditRoutes(app: FastifyInstance) {
  app.get<{ Querystring: { agent?: string; from?: string; to?: string } }>("/audit", async (req) => {
    const { agent, from, to } = req.query;

    const events = await prisma.event.findMany({
      where: {
        agent: agent ?? undefined,
        timestamp: {
          gte: from ? new Date(from) : undefined,
          lte: to ? new Date(to) : undefined,
        },
      },
      orderBy: { timestamp: "desc" },
      take: 500,
    });

    return serializeBigInts(events);
  });

  app.get("/audit/export", async (_req, reply) => {
    const rows = await prisma.event.findMany({ orderBy: { timestamp: "desc" } });
    const header = "timestamp,agent,counterparty,amount,decision\n";
    const csv = rows
      .map((r) => `${r.timestamp.toISOString()},${r.agent},${r.counterparty},${r.amount.toString()},${r.decision}`)
      .join("\n");
    reply.header("Content-Type", "text/csv").send(header + csv);
  });
}