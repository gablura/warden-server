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

/// The leadership loop. Tries to acquire the indexer lock, and — critically —
/// KEEPS TRYING until it succeeds: a leadership check that only runs at boot
/// means a crashed leader is never replaced and indexing stops silently
/// until someone manually restarts a replica. Non-leaders retry every
/// RETRY_DELAY; once a replica acquires the lock, onLeadershipAcquired runs
/// exactly once (the caller's watchers start there) and this resolves.
///
/// Duplicate-watcher safety: if the leader's lock connection later dies, the
/// lock is released and another replica takes over while the old leader's
/// watchers may still be running — two watchers then race on the same
/// events. That race is safe by construction (claim-first ProcessedLog
/// inserts: the loser's claim insert loses on the unique constraint and the
/// event is skipped), but lock loss is still logged loudly (see the error
/// handlers in acquireIndexerLeadership) because wasted RPC calls and
/// flapping are worth knowing about.
const RETRY_DELAY_MS = 30_000;

const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/// Minimal logger surface — satisfied by pino (app.log in server.ts).
export interface LeadershipLogger {
  info: (msg: string) => void;
  warn: (msg: string) => void;
  error: (msg: string, err?: unknown) => void;
}

export async function runIndexerLeadership(
  onLeadershipAcquired: () => Promise<void>,
  log: LeadershipLogger,
): Promise<void> {
  for (;;) {
    try {
      if (await acquireIndexerLeadership()) {
        log.info("Indexer lock acquired — starting watchers");
        await onLeadershipAcquired();
        return;
      }
      log.warn(`Another instance holds the indexer lock — running API-only, retrying in ${RETRY_DELAY_MS / 1000}s`);
    } catch (err) {
      // A DB problem during acquisition must not kill the loop: the lock is
      // how indexing survives a primary's outage, so keep retrying.
      log.error("Indexer leadership check failed — retrying", err);
    }
    await wait(RETRY_DELAY_MS);
  }
}

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
      // long as this connection does. If the connection DIES, Postgres
      // releases the lock and another replica can take over while this
      // process's watchers still run — safe (see runIndexerLeadership on
      // duplicate-watcher races) but loud, so surface it.
      client.on("error", (err) => {
        console.error("[indexer-leader] indexer lock connection error — the lock may have been released:", err);
      });
      client.on("end", () => {
        console.error("[indexer-leader] indexer lock connection closed — the lock has been released");
      });
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
