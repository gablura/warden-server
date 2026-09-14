/// Thrown when authoritative on-chain state cannot be read — the RPC is
/// unreachable, times out, or the call reverts.
///
/// This exists so callers can fail closed. For spend and cap values there
/// is no safe fallback: serving an indexed row instead would hand the
/// dashboard a figure the chain has not confirmed, and the indexed
/// `spent_today` column is known to be stale across the UTC day boundary.
/// A 503 that the client retries is the correct outcome.
export class ChainUnavailableError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "ChainUnavailableError";
  }
}
