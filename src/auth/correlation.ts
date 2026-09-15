import { AsyncLocalStorage } from "node:async_hooks";
import { randomUUID } from "node:crypto";

/// Correlation ID for end-to-end traceability (hardening review §5).
///
/// Every gas-spending API request gets a unique ID that follows the thread:
///   API request → tx submission → operator_actions row → response / WS broadcast
///
/// Implemented via AsyncLocalStorage so the ID propagates implicitly through
/// the promise chain (including the txQueue serialization) without threading
/// a parameter through every call site. The store is request-scoped — each
/// inbound request gets its own context, so concurrent requests never share
/// an ID.

const store = new AsyncLocalStorage<string>();

/// Run a function with the given correlation ID as the ambient context.
export function runWithCorrelation<T>(id: string, fn: () => T): T {
  return store.run(id, fn);
}

/// Returns the correlation ID for the current request, or undefined if called
/// outside a request context (e.g. during boot, in background tasks).
export function getCorrelationId(): string | undefined {
  return store.getStore();
}

/// Generate a new correlation ID. Called once per request in the auth preHandler.
export function generateCorrelationId(): string {
  return randomUUID();
}

// Fastify request augmentation — downstream handlers and the tx queue read
// req.correlationId to tie DB rows and logs to the originating API request.
declare module "fastify" {
  interface FastifyRequest {
    correlationId?: string;
  }
}
