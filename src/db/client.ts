import { PrismaClient } from "@prisma/client";
import { PrismaPg } from "@prisma/adapter-pg";
import { config } from "../config.js";

// Prisma 7 requires an explicit driver adapter — the client no longer
// opens a connection on its own from a schema-level url.
const adapter = new PrismaPg({ connectionString: config.DATABASE_URL });

export const prisma = new PrismaClient({ adapter });

/// Fastify's JSON serializer throws on raw BigInt (amounts, requestId).
/// Route handlers should pass their Prisma results through this before
/// returning them, rather than reaching for Number() and risking
/// precision loss on large USDC amounts.
export function serializeBigInts<T>(value: T): T {
  return JSON.parse(JSON.stringify(value, (_key, v) => (typeof v === "bigint" ? v.toString() : v)));
}