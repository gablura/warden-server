import type { FastifyInstance } from "fastify";
import { prisma, serializeBigInts } from "../db/client.js";
import { cursorQuerySchema, cursorPaginatedQuery, cursorWhere, encodeCursor } from "../db/pagination.js";

export async function auditRoutes(app: FastifyInstance) {
  app.get<{
    Querystring: { agent?: string; from?: string; to?: string; limit?: string; cursor?: string };
  }>("/audit", async (req) => {
    const { agent, from, to, limit: rawLimit, cursor: rawCursor } = req.query;

    const result = await cursorPaginatedQuery(
      (take, cursor) =>
        prisma.event.findMany({
          where: {
            agent: agent ?? undefined,
            timestamp: {
              gte: from ? new Date(from) : undefined,
              lte: to ? new Date(to) : undefined,
            },
            ...(cursor ? cursorWhere(cursor, "desc") : {}),
          },
          orderBy: [{ timestamp: "desc" }, { id: "desc" }],
          take,
        }),
      { limit: rawLimit, cursor: rawCursor },
    );

    const last = result.data[result.data.length - 1];
    return serializeBigInts({
      ...result,
      nextCursor: result.hasMore && last ? encodeCursor(last.id, last.timestamp) : null,
    });
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
