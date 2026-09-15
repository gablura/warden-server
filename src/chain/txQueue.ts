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
const queues = new Map<string, Promise<unknown>>();

export function serializeTx<T>(account: string, fn: () => Promise<T>): Promise<T> {
  const previous = queues.get(account) ?? Promise.resolve();
  // Attach fn to the chain under both outcomes so a rejection upstream
  // never leaves the queue stuck.
  const run = previous.then(fn, fn);
  // The stored tail swallows errors: it exists only for ordering. The
  // caller still gets `run` with the real result or real rejection.
  queues.set(account, run.catch(() => undefined));
  return run;
}
