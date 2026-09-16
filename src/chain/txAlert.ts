import { broadcastSystem } from "../ws/broadcast.js";

/// Transaction-submission failure burst detection (hardening review §5.2:
/// "Monitoring and alerting, not just logging" — failed transactions are
/// named there alongside indexer lag and repeated auth failures).
///
/// A single failed submission is usually an RPC blip or a reverted call the
/// route already surfaces as an error response; a BURST means the chain,
/// the RPC endpoint, or a signing key has a real problem and someone should
/// be paged. Same shape as auth/failureAlert.ts: an error-level log line
/// (one per burst, not per failure) plus a WS broadcast the dashboard can
/// surface live. The broadcast carries no sensitive detail — the function
/// name and deployment key are operational facts every operator may see.

const WINDOW_MS = 60_000;
const BURST_THRESHOLD = 5;

let recentFailures: number[] = [];

export function recordTxFailure(detail: { functionName: string; deployment: string }) {
  const now = Date.now();
  const windowStart = now - WINDOW_MS;

  recentFailures = recentFailures.filter((t) => t > windowStart);
  recentFailures.push(now);

  if (recentFailures.length === BURST_THRESHOLD) {
    alertTxFailures({ count: recentFailures.length, functionName: detail.functionName, deployment: detail.deployment });
  }
}

let logFn: ((obj: object, msg: string) => void) | null = null;

/// Called once from server.ts so alerts use the app's pino logger rather
/// than this module reaching into a global. Before it's wired, alerts still
/// broadcast over WS.
export function setTxAlertLogger(log: (obj: object, msg: string) => void) {
  logFn = log;
}

function alertTxFailures(alert: { count: number; functionName: string; deployment: string }) {
  logFn?.(alert, "tx_failure_burst — repeated transaction submission failures");
  broadcastSystem({ type: "tx_alert", ...alert, at: new Date().toISOString() });
}