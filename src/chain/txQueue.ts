import { AsyncLocalStorage } from "node:async_hooks";

/// Serializes transaction submission per signing account.
///
/// Viem's wallet writes fetch the account's nonce at send time. Two write
/// calls issued close together (two API requests hitting the same admin or
/// approver wallet) can both read the same pending nonce, and one of the
/// transactions then fails with a replacement/underpriced error — a wasted
/// gas attempt caused purely by client-side concurrency. Each signing
/// account gets its own promise chain: writes queue up and run strictly one
/// at a time, so nonce ordering is deterministic.
///
/// Keys are arbitrary labels; use one per wallet ("admin", "approver").
/// A failed transaction does not stall the queue — the next write runs
/// regardless of the previous outcome.
///
/// AsyncLocalStorage context (correlation IDs) is captured per-call so that
/// each transaction records the correlation ID of the request that triggered
/// it, even though they share one serialized promise chain.
const queues = new Map<string, Promise<unknown>>();

export function serializeTx<T>(account: string, fn: () => Promise<T>): Promise<T> {
  const previous = queues.get(account) ?? Promise.resolve();
  // Capture the calling request's AsyncLocalStorage context so fn runs
  // with its own correlation ID, not whichever request happened to chain
  // onto the previous promise.
  const ctx = AsyncLocalStorage.snapshot();
  const run = previous.then(() => ctx(fn), () => ctx(fn));
  // The stored tail swallows errors: it exists only for ordering. The
  // caller still gets `run` with the real result or real rejection.
  queues.set(account, run.catch(() => undefined));
  return run;
}
