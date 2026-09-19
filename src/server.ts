import Fastify from "fastify";
import type { FastifyRequest } from "fastify";
import cors from "@fastify/cors";
import websocket from "@fastify/websocket";
import rateLimit from "@fastify/rate-limit";
import { config } from "./config.js";
import { ChainUnavailableError } from "./chain/errors.js";
import { setTxAlertLogger } from "./chain/txAlert.js";
import { agentRoutes } from "./routes/agents.js";
import { policyRoutes } from "./routes/policies.js";
import { approvalRoutes } from "./routes/approvals.js";
import { auditRoutes } from "./routes/audit.js";
import { statusRoutes } from "./routes/status.js";
import { authRoutes } from "./routes/auth/index.js";
import { clerkWebhookRoutes } from "./routes/webhooks.js";
import { registerClient, registerAnonymousClient } from "./ws/broadcast.js";
import { deploymentKey, resolveDeployment } from "./chain/orgContracts.js";
import { setAuthAlertLogger } from "./auth/failureAlert.js";
import { runIndexerLeadership } from "./indexer/leader.js";
import { watchPaymentEvents } from "./indexer/watchPaymentEvents.js";
import { watchPolicyEvents } from "./indexer/watchPolicyEvents.js";

// The error handler receives `unknown` in Fastify 5, so narrow it explicitly
// rather than trusting the shape of a thrown value.
function errorFields(err: unknown) {
  const candidate = err as { statusCode?: unknown; code?: unknown };
  return {
    statusCode: typeof candidate.statusCode === "number" ? candidate.statusCode : 500,
    code: typeof candidate.code === "string" ? candidate.code : "internal_error",
  };
}

const app = Fastify({ logger: true });

// ── Raw-body capture (for HMAC verification of the exact wire bytes) ────
//
// Request signatures cover the body AS SENT (see auth/requestSignature.ts),
// so the server must hash the untouched request bytes, not a re-serialization
// of the parsed object — any client key-order or whitespace difference would
// otherwise fail verification. The content-type parser below captures the
// raw string alongside parsing, storing it on req.rawBody (declared in
// requestSignature.ts).
//
// Fastify has no global JSON.parse hook for body parsing — the documented
// way to see the raw body is a content-type parser. Registering one for
// application/json preserves Fastify's default parsing behavior.
app.addContentTypeParser(
  "application/json",
  { parseAs: "string" },
  (req, body, done) => {
    // The parser receives the raw string; store it and hand Fastify the
    // parsed object exactly as its default parser would.
    (req as FastifyRequest).rawBody = body as string;
    try {
      done(null, JSON.parse(body as string));
    } catch (err) {
      (done as (e: unknown, v?: unknown) => void)(err);
      return;
    }
  },
);

// ── Transaction-failure alerting (hardening review §5.2) ────────────────
// Failed tx submissions burst-alert through the app's pino logger (see
// chain/txAlert.ts) — the same one-log-line-per-burst + WS broadcast shape
// as auth-failure alerting.
setTxAlertLogger((obj, msg) => app.log.error(obj, msg));

// Surface the request-signing enforcement posture at boot. A migration
// window that closes silently is how "temporary" exceptions become
// permanent, so the config is always stated in the logs — including the
// warning case, which is the signal to set an UNSIGNED_REQUESTS_ALLOWED_UNTIL
// deadline or flip REQUIRE_SIGNED_REQUESTS.
if (config.REQUIRE_SIGNED_REQUESTS) {
  app.log.info("Request signing enforced: unsigned api-key requests are rejected");
} else if (config.UNSIGNED_REQUESTS_ALLOWED_UNTIL !== undefined) {
  app.log.info(`Request signing becomes required after ${config.UNSIGNED_REQUESTS_ALLOWED_UNTIL} — unsigned api-key requests accepted until then`);
} else {
  app.log.warn("Request signing NOT enforced and no UNSIGNED_REQUESTS_ALLOWED_UNTIL deadline set — unsigned api-key requests are accepted indefinitely");
}

// Auth-failure bursts log through the app's pino logger (see failureAlert.ts).
setAuthAlertLogger((obj, msg) => app.log.error(obj, msg));

// WebSocket handshakes are not covered by the CORS plugin — same-origin
// policy does not gate the upgrade request, so any page in any browser could
// otherwise open a socket to /ws and read the live payment feed. The origin
// check below is the WS equivalent of the CORS config and must list the same
// origins. Missing Origin (server-to-server clients, curl) is allowed; a
// *mismatched* Origin is a browser and gets dropped.
const allowedOrigins = new Set(
  config.CORS_ORIGIN.split(",").map((o) => o.trim()).filter(Boolean),
);

await app.register(cors, { origin: config.CORS_ORIGIN, credentials: true });
await app.register(websocket);
await app.register(rateLimit, { max: 300, timeWindow: "1 minute" }); // Default rate limit for all routes

// The one place that catches broadly. Chain reads are fail-closed: the agent
// routes serve policy caps and live spend straight from PolicyRegistry, and the
// indexed fallback for those values is known to be stale across the UTC day
// boundary, so an unreadable chain becomes a retryable 503 rather than a
// plausible-looking wrong number.
app.setErrorHandler((err, req, reply) => {
  if (err instanceof ChainUnavailableError) {
    req.log.error({ err }, "PolicyRegistry read failed");
    return reply.code(503).send({ error: "chain_unavailable", message: err.message });
  }

  const { statusCode, code } = errorFields(err);
  req.log.error({ err }, "Unhandled error");

  // 5xx bodies stay generic: the real message is in the log, and internal
  // failure text (SQL, RPC payloads) has no business reaching a dashboard client.
  const message = statusCode >= 500 ? "Something went wrong" : err instanceof Error ? err.message : "Request failed";
  return reply.code(statusCode).send({ error: code, message });
});

// Dashboard clients connect here for live pushes (new payments, resolved
// approvals) instead of polling the REST routes.
//
// Identity: on mainnet the upgrade requires a short-lived ticket from
// POST /auth/ws-ticket, and the connection's feed is scoped to the ticket's
// org deployment for life — a wildcard subscriber can only ever see their
// own org's deployment (hardening review §1, multi-tenant /ws). Testnet
// keeps the anonymous global feed: one shared playground, no orgs to
// isolate. The origin check below remains a separate, defense-in-depth
// boundary in both modes.
app.register(async (scope) => {
  scope.get("/ws", { websocket: true }, (socket, req) => {
    const origin = req.headers.origin;
    if (origin !== undefined && !allowedOrigins.has(origin)) {
      scope.log.warn({ origin, ip: req.ip }, "rejected websocket upgrade from disallowed origin");
      socket.close(1008, "origin not allowed");
      return;
    }

    const ticket = (req.query as { ticket?: string }).ticket;
    if (config.WARDEN_NETWORK === "mainnet") {
      // Registration is async (scope resolution hits the DB) but the handler
      // has returned, so errors must be handled here: an unresolved scope
      // (misconfigured org, DB failure) closes the socket instead of leaving
      // it dangling — and must never surface as an unhandled rejection.
      registerClient(socket, ticket, async (orgId) => {
        const deployment = await resolveDeployment(orgId);
        return deploymentKey(deployment);
      }).catch((err) => {
        scope.log.error({ err, ip: req.ip }, "websocket scope resolution failed");
        socket.close(1011, "scope resolution failed");
      });
    } else {
      registerAnonymousClient(socket);
    }
  });
});

await app.register(clerkWebhookRoutes);
await app.register(agentRoutes);
await app.register(policyRoutes);
await app.register(approvalRoutes);
await app.register(auditRoutes);
await app.register(statusRoutes);
await app.register(authRoutes);

app.get("/health", async () => ({ ok: true }));

// Start the chain event indexers. A Postgres advisory lock elects a single
// watcher instance — with more than one replica, every other replica skips
// starting its watchers instead of processing every event multiple times
// (which would multiply spend totals and duplicate audit rows).
//
// Election runs through runIndexerLeadership, which RETRIES every 30s until
// it acquires the lock: a boot-time-only check would mean a crashed leader
// is never replaced and indexing stops silently until someone restarts a
// replica. Duplicate-watcher safety and lock-loss behavior are documented in
// indexer/leader.ts.
app.log.info("Starting chain event indexer leadership loop...");
runIndexerLeadership(async () => {
  // Each watcher backfills from its persisted checkpoint before going
  // live, so a restart resumes instead of skipping events.
  await Promise.all([watchPaymentEvents(), watchPolicyEvents()]);
  app.log.info("Chain event indexers started successfully (this instance holds the indexer lock)");
}, app.log).catch((err) => {
  app.log.error({ err }, "Indexer leadership loop failed unexpectedly");
});

app.listen({ port: config.PORT, host: "0.0.0.0" }).catch((err) => {
  app.log.error({ err }, "Failed to start server");
  process.exit(1);
});