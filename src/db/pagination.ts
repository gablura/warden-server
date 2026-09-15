import { z } from "zod";

export const DEFAULT_LIMIT = 50;
export const MAX_LIMIT = 200;

// limit-only schema for routes without cursor support (agents, approvals)
export const limitQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(MAX_LIMIT).optional(),
});

// limit + cursor schema for events-backed routes (audit, agents/:address)
export const cursorQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(MAX_LIMIT).optional(),
  cursor: z.string().optional(),
});

export type LimitQuery = z.infer<typeof limitQuerySchema>;

export function coerceLimit(raw: unknown): number {
  const n = typeof raw === "number" && Number.isFinite(raw) ? Math.trunc(raw) : DEFAULT_LIMIT;
  return Math.min(Math.max(n, 1), MAX_LIMIT);
}

// --- cursor encoding / decoding ---

// Opaque to clients. The shape is an internal detail; changing it doesn't
// break consumers because they only pass the string back verbatim.
interface CursorPayload {
  id: number;
  timestamp: string; // ISO-8601
}

export function encodeCursor(id: number, timestamp: Date): string {
  return Buffer.from(JSON.stringify({ id, timestamp: timestamp.toISOString() })).toString("base64url");
}

function decodeCursor(raw: string): CursorPayload | null {
  try {
    const payload: CursorPayload = JSON.parse(Buffer.from(raw, "base64url").toString());
    if (typeof payload.id !== "number" || typeof payload.timestamp !== "string") return null;
    if (isNaN(new Date(payload.timestamp).getTime())) return null;
    return payload;
  } catch {
    return null;
  }
}

// --- paginated query types ---

export type PaginatedResponse<T> = { data: T[]; hasMore: boolean };

/**
 * Simple limit-only paginated query for routes without cursor support.
 * Fetches `limit + 1` rows, strips the extra to produce `hasMore`.
 */
export async function paginatedQuery<T>(
  findMany: (take: number) => Promise<T[]>,
  limit: unknown,
): Promise<PaginatedResponse<T>> {
  const effectiveLimit = coerceLimit(limit);
  const rows = await findMany(effectiveLimit + 1);
  const hasMore = rows.length > effectiveLimit;
  if (hasMore) rows.pop();
  return { data: rows, hasMore };
}

type OrderDirection = "asc" | "desc";

interface CursorField {
  id: number;
  timestamp: Date;
}

/**
 * Keyset-paginated query for models with (timestamp, id) ordering.
 *
 * Fetches `limit + 1` rows starting after the decoded cursor (if any),
 * then strips the extra row to produce `hasMore`. The cursor is opaque
 * to clients — they receive it from one response and pass it back on
 * the next; the encoding is an internal detail.
 *
 * Works correctly under concurrent writes: new rows landing between
 * page fetches never cause skips or duplicates because each page is
 * anchored to a stable (timestamp, id) position, not an offset.
 */
export async function cursorPaginatedQuery<T extends CursorField>(
  findMany: (take: number, cursor?: CursorPayload) => Promise<T[]>,
  query: { limit?: string; cursor?: string },
): Promise<PaginatedResponse<T>> {
  const effectiveLimit = coerceLimit(query.limit);
  const cursor = query.cursor ? decodeCursor(query.cursor) : null;
  const rows = await findMany(effectiveLimit + 1, cursor ?? undefined);
  const hasMore = rows.length > effectiveLimit;
  if (hasMore) rows.pop();
  return { data: rows, hasMore };
}

// --- Prisma where-clause helpers for cursor queries ---

/**
 * Builds the `where` clause for a keyset cursor on (timestamp, id).
 *
 * For DESC ordering ("before this point"): (timestamp, id) < (cursor.timestamp, cursor.id)
 * For ASC ordering ("after this point"):  (timestamp, id) > (cursor.timestamp, cursor.id)
 */
export function cursorWhere(
  cursor: CursorPayload,
  direction: OrderDirection,
): { OR: Array<Record<string, unknown>> } {
  const tsField = new Date(cursor.timestamp);
  if (direction === "desc") {
    return {
      OR: [
        { timestamp: { lt: tsField } },
        { timestamp: tsField, id: { lt: cursor.id } },
      ],
    };
  }
  return {
    OR: [
      { timestamp: { gt: tsField } },
      { timestamp: tsField, id: { gt: cursor.id } },
    ],
  };
}
