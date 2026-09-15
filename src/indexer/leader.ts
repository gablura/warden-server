import pg from "pg";
import { config } from "../config.js";

/// Single-writer election for the indexers, via a Postgres advisory lock.
///
/// If warden-server is ever run as more than one replica, every replica would
/// otherwise run its own watchers and every on-chain event would be processed
/// once per replica — multiplying spend totals and duplicating audit rows.
/// The lock is a lightweight way to guarantee exactly one replica's watchers
/// are active without a separate indexer process or a consensus dependency.
///
/// Implementation note — the lock MUST be held on a dedicated connection,
/// not through `prisma.$queryRaw`. Advisory locks are session-scoped, and
/// Prisma's underlying pg pool closes idle connections (~10s), which ends
/// the session and silently releases the lock — found live during testing:
/// two replicas both "acquired" the lock minutes apart. A dedicated client
/// stays connected for the life of the process, so the lock is held until
/// the process exits (which is also the release path: a crashed holder
/// always loses the lock automatically, and a live holder keeps it for free).
const LOCK_KEY = "warden-indexer";

let lockHolder: pg.Client | null = null;

export async function acquireIndexerLeadership(): Promise<boolean> {
  const client = new pg.Client({ connectionString: config.DATABASE_URL });

  try {
    await client.connect();
    const result = await client.query<{ locked: boolean }>(
      "SELECT pg_try_advisory_lock(hashtext($1)) AS locked",
      [LOCK_KEY],
    );

    if (result.rows[0]?.locked === true) {
      // Keep the session open for the process lifetime — the lock lives as
      // long as this connection does.
      lockHolder = client;
      return true;
    }

    await client.end();
    return false;
  } catch (err) {
    // Never leave a half-connected client dangling; leadership failure here
    // is a DB problem and propagates to the caller.
    await client.end().catch(() => {});
    throw err;
  }
}

/// Explicit release for tests/graceful shutdown. Safe to call when the lock
/// was never acquired.
export async function releaseIndexerLeadership(): Promise<void> {
  if (!lockHolder) return;
  const client = lockHolder;
  lockHolder = null;
  await client.end().catch(() => {});
}
