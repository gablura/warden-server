import Fastify from "fastify";
import cors from "@fastify/cors";
import websocket from "@fastify/websocket";
import rateLimit from "@fastify/rate-limit";
import { config } from "./config.js";
import { ChainUnavailableError } from "./chain/errors.js";
import { agentRoutes } from "./routes/agents.js";
import { policyRoutes } from "./routes/policies.js";
import { approvalRoutes } from "./routes/approvals.js";
import { auditRoutes } from "./routes/audit.js";
import { statusRoutes } from "./routes/status.js";
import { registerClient } from "./ws/broadcast.js";
import { setAuthAlertLogger } from "./auth/failureAlert.js";
import { acquireIndexerLeadership } from "./indexer/leader.js";
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

await app.register(cors, { origin: config.CORS_ORIGIN });
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
app.register(async (scope) => {
  scope.get("/ws", { websocket: true }, (socket, req) => {
    const origin = req.headers.origin;
    if (origin !== undefined && !allowedOrigins.has(origin)) {
      scope.log.warn({ origin, ip: req.ip }, "rejected websocket upgrade from disallowed origin");
      socket.close(1008, "origin not allowed");
      return;
    }
    registerClient(socket);
  });
});

await app.register(agentRoutes);
await app.register(policyRoutes);
await app.register(approvalRoutes);
await app.register(auditRoutes);
await app.register(statusRoutes);

app.get("/health", async () => ({ ok: true }));

// Start the chain event indexers. A Postgres advisory lock elects a single
// watcher instance — with more than one replica, every other replica skips
// starting its watchers instead of processing every event multiple times
// (which would multiply spend totals and duplicate audit rows).
app.log.info("Starting chain event indexers...");
try {
  const isLeader = await acquireIndexerLeadership();
  if (isLeader) {
    // Each watcher backfills from its persisted checkpoint before going
    // live, so a restart resumes instead of skipping events.
    await Promise.all([watchPaymentEvents(), watchPolicyEvents()]);
    app.log.info("Chain event indexers started successfully (this instance holds the indexer lock)");
  } else {
    app.log.warn("Another instance holds the indexer lock — running API-only, no watchers started");
  }
} catch (err) {
  app.log.error({ err }, "Failed to start chain event indexers");
  // Continue running the server even if indexers fail - the API will still work
  // but won't have live chain updates until the indexers are fixed
}

app.listen({ port: config.PORT, host: "0.0.0.0" }).catch((err) => {
  app.log.error({ err }, "Failed to start server");
  process.exit(1);
});