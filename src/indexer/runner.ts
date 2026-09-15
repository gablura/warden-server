import type { Abi } from "viem";
import { publicClient } from "../chain/client.js";
import { prisma } from "../db/client.js";

/// Shared event-watcher machinery. Both indexers (payments, policies) run
/// through this instead of calling watchContractEvent directly, so every
/// watcher gets the same guarantees for free:
///
/// 1. **Idempotent processing.** Each log is claimed by inserting a
///    ProcessedLog row (unique on tx hash + log index) *before* any side
///    effect runs. A unique violation means the event was already applied
///    and it is skipped — so an overlapping backfill or a replayed block
///    range can never double-increment spentToday or duplicate audit rows.
///    Claim-first is deliberate over side-effect-first: for spend totals,
///    a lost increment (logged loudly) is recoverable; a doubled one is
///    silent and wrong.
/// 2. **Persisted checkpoint.** After each batch, the watcher's
///    IndexerCheckpoint advances to the highest block whose events all
///    processed cleanly — a failed event holds the checkpoint back, so the
///    next boot's backfill retries it instead of silently skipping.
/// 3. **Backfill on boot.** If a checkpoint exists, historical logs from
///    lastBlock + 1 are replayed through the same idempotent path before
///    (actually, concurrently with) the live subscription, closing the
///    restart-gap the review flagged. First boot records the current head
///    as the baseline, matching the previous live-only behavior.

const BACKFILL_CHUNK = 2_000n;
const BACKFILL_CHUNK_DELAY_MS = 400;
const BACKFILL_RETRY_DELAY_MS = 2_000;

// Backfills from all watchers share one serialized queue with a pause
// between chunks. First boot or a long gap can mean many watchers each
// requesting hundreds of blocks at once — hammering the RPC in parallel
// trips its rate limiter (seen live on Arc testnet: -32005 on seven
// concurrent eth_getLogs bursts). Live watchers keep running during the
// backfill, so serializing costs nothing in freshness.
let backfillTail: Promise<void> = Promise.resolve();

function queueBackfill(run: () => Promise<void>): Promise<void> {
  const result = backfillTail.then(run, run);
  backfillTail = result.catch(() => {});
  return result;
}

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export interface ProcessableLog {
  args: Record<string, unknown>;
  blockNumber: bigint;
  transactionHash: `0x${string}`;
  logIndex: number;
}

type LogHandler = (log: ProcessableLog) => Promise<void>;

interface WatcherConfig {
  /// Stable checkpoint key, e.g. "payments", "policies".
  name: string;
  address: `0x${string}`;
  abi: Abi;
  eventName: string;
  onLog: LogHandler;
}

/// Starts a watcher: backfills from the persisted checkpoint (if any) and
/// subscribes to live events. Resolves once the backfill has finished; the
/// live subscription keeps running for the life of the process. Errors from
/// a single log are logged and do not stop the watcher — mirroring the
/// previous per-event error handling, a bad event must not kill the indexer.
export async function startWatcher(cfg: WatcherConfig): Promise<void> {
  publicClient.watchContractEvent({
    address: cfg.address,
    abi: cfg.abi,
    eventName: cfg.eventName,
    onLogs: (logs) => processBatch(cfg, logs as unknown as ProcessableLog[]),
  });

  await queueBackfill(() => backfill(cfg));
}

async function backfill(cfg: WatcherConfig) {
  const checkpoint = await prisma.indexerCheckpoint.findUnique({ where: { watcher: cfg.name } });

  if (!checkpoint) {
    // First boot with this watcher: record the current head as the baseline.
    // No historical events are processed (same as the old live-only behavior);
    // from now on every restart resumes from here instead of skipping ahead.
    const head = await publicClient.getBlockNumber();
    await prisma.indexerCheckpoint.create({ data: { watcher: cfg.name, lastBlock: head } });
    return;
  }

  let from = checkpoint.lastBlock + 1n;
  let head: bigint;
  try {
    head = await publicClient.getBlockNumber();
  } catch (err) {
    console.error(`[${cfg.name}] backfill aborted: could not read the chain head:`, err);
    return;
  }

  if (from > head) return;

  // Chunked so a long-running gap after extended downtime doesn't build one
  // enormous eth_getLogs request that RPC providers refuse — and paced, so
  // consecutive chunks don't trip the provider's rate limiter. A chunk that
  // still fails is retried with backoff; giving up on a chunk leaves the
  // checkpoint behind and the whole range retries on next boot, so the only
  // cost of permanent failure is an older-and-older gap, never a skipped one.
  while (from <= head) {
    const to = from + BACKFILL_CHUNK - 1n > head ? head : from + BACKFILL_CHUNK - 1n;
    let processed = false;
    for (let attempt = 1; attempt <= 3 && !processed; attempt++) {
      try {
        const logs = await publicClient.getContractEvents({
          address: cfg.address,
          abi: cfg.abi,
          eventName: cfg.eventName as never,
          fromBlock: from,
          toBlock: to,
        });
        await processBatch(cfg, logs as unknown as ProcessableLog[]);
        processed = true;
      } catch (err) {
        if (attempt === 3) {
          console.error(`[${cfg.name}] backfill failed for blocks ${from}-${to} after 3 attempts:`, err);
          return; // Checkpoint is still behind; the next boot retries this range.
        }
        await delay(BACKFILL_RETRY_DELAY_MS * attempt);
      }
    }
    from = to + 1n;
    if (from <= head) await delay(BACKFILL_CHUNK_DELAY_MS);
  }
}

async function processBatch(cfg: WatcherConfig, logs: ProcessableLog[]) {
  if (logs.length === 0) return;

  // Logs arrive in block order; the checkpoint may only advance past a block
  // whose events all succeeded, so the first failure caps it for this batch.
  let checkpointBlock: bigint | undefined;
  let failed = false;

  for (const log of logs) {
    try {
      const claimed = await claimLog(cfg.name, log);
      if (!claimed) continue; // Already applied — the whole point of the marker.
      await cfg.onLog(log);
      if (!failed) checkpointBlock = log.blockNumber;
    } catch (err) {
      failed = true;
      console.error(`[${cfg.name}] error processing event in tx ${log.transactionHash}:`, err);
    }
  }

  if (checkpointBlock !== undefined) {
    await prisma.indexerCheckpoint.upsert({
      where: { watcher: cfg.name },
      create: { watcher: cfg.name, lastBlock: checkpointBlock },
      update: { lastBlock: checkpointBlock },
    });
  }
}

/// Inserts the processed-marker for this log. Returns false when the marker
/// already exists (event was applied by a previous run), true when this run
/// owns the side effects. Any other insert error propagates.
async function claimLog(watcher: string, log: ProcessableLog): Promise<boolean> {
  try {
    await prisma.processedLog.create({
      data: { txHash: log.transactionHash, logIndex: log.logIndex, watcher },
    });
    return true;
  } catch (err) {
    if (isUniqueViolation(err)) return false;
    throw err;
  }
}

function isUniqueViolation(err: unknown): boolean {
  return typeof err === "object" && err !== null && (err as { code?: string }).code === "P2002";
}
