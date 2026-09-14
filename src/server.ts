import Fastify from "fastify";
import cors from "@fastify/cors";
import websocket from "@fastify/websocket";
import { config } from "./config.js";
import { agentRoutes } from "./routes/agents.js";
import { policyRoutes } from "./routes/policies.js";
import { approvalRoutes } from "./routes/approvals.js";
import { auditRoutes } from "./routes/audit.js";
import { registerClient } from "./ws/broadcast.js";
import { watchPaymentEvents } from "./indexer/watchPaymentEvents.js";
import { watchPolicyEvents } from "./indexer/watchPolicyEvents.js";

const app = Fastify({ logger: true });

await app.register(cors, { origin: config.CORS_ORIGIN });
await app.register(websocket);

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