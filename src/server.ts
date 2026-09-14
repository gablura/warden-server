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
import { registerClient } from "./ws/broadcast.js";
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
  scope.get("/ws", { websocket: true }, (socket) => registerClient(socket));
});

await app.register(agentRoutes);
await app.register(policyRoutes);
await app.register(approvalRoutes);
await app.register(auditRoutes);

app.get("/health", async () => ({ ok: true }));

// Start the chain event indexers
app.log.info("Starting chain event indexers...");
try {
  watchPaymentEvents();
  watchPolicyEvents();
  app.log.info("Chain event indexers started successfully");
} catch (err) {
  app.log.error({ err }, "Failed to start chain event indexers");
  // Continue running the server even if indexers fail - the API will still work
  // but won't have live chain updates until the indexers are fixed
}

app.listen({ port: config.PORT, host: "0.0.0.0" }).catch((err) => {
  app.log.error({ err }, "Failed to start server");
  process.exit(1);
});