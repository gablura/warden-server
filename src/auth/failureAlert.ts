import { broadcast } from "../ws/broadcast.js";

/// Auth-failure burst detection. The hardening review's point: a burst of
/// 401s on the gas-spending routes is exactly the thing that should page
/// someone, not sit in a log file. There's no pager wired up yet, so the
/// alert goes two places that already exist: an error-level log line
/// (grep/alert-tooling friendly, one per burst, not per request) and the
/// WebSocket hub, so the dashboard can surface it live.
///
/// Sliding window per source IP. Config-free by design: the threshold is a
/// detection sensitivity, not a policy knob, and the global rate limiter
/// already caps how fast the window can fill.

const WINDOW_MS = 60_000;
const BURST_THRESHOLD = 10;

const failures = new Map<string, number[]>();

export function recordAuthFailure(ip: string, detail: { role: string; reason: string }) {
  const now = Date.now();
  const windowStart = now - WINDOW_MS;

  const recent = (failures.get(ip) ?? []).filter((t) => t > windowStart);
  recent.push(now);
  failures.set(ip, recent);

  // Opportunistic cleanup of IPs that have gone quiet.
  if (failures.size > 1_000) {
    for (const [key, times] of failures) {
      if (times.every((t) => t <= windowStart)) failures.delete(key);
    }
  }

  if (recent.length === BURST_THRESHOLD) {
    // Fires once when the burst crosses the threshold, not on every
    // subsequent failure — the alert is the signal, not the noise.
    alertAuthBurst({ ip, count: recent.length, role: detail.role, lastReason: detail.reason });
  }
}

let logFn: ((obj: object, msg: string) => void) | null = null;

/// Called once from server.ts so alerts use the app's pino logger rather
/// than this module reaching into a global. Before it's wired, alerts still
/// broadcast over WS.
export function setAuthAlertLogger(log: (obj: object, msg: string) => void) {
  logFn = log;
}

function alertAuthBurst(alert: { ip: string; count: number; role: string; lastReason: string }) {
  logFn?.(alert, "auth_failure_burst — possible credential stuffing or leaked key");
  broadcast({ type: "auth_alert", ...alert, at: new Date().toISOString() });
}
