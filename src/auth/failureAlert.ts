import { broadcastSystem } from "../ws/broadcast.js";

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
  // The full alert (with the source IP) goes to the logs only. The WS
  // broadcast deliberately omits the IP: system events reach wildcard
  // subscribers in EVERY deployment scope, so on mainnet an attacker IP
  // would cross tenant boundaries — infrastructure data other orgs'
  // dashboards have no business seeing. The role and reason are enough for
  // a dashboard to surface "suspicious activity"; the IP is an
  // operator-lookup detail, and the logs are where operators look.
  logFn?.(alert, "auth_failure_burst — possible credential stuffing or leaked key");
  broadcastSystem({
    type: "auth_alert",
    count: alert.count,
    role: alert.role,
    lastReason: alert.lastReason,
    at: new Date().toISOString(),
  });
}
