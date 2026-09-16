import type { WebSocket } from "@fastify/websocket";

/// Scoped WebSocket broadcast (hardening review §1 — unscoped /ws broadcast).
///
/// Every connected client starts with no subscriptions and sees nothing until
/// it sends a subscription message. A client can subscribe to:
///   - Specific agents: only events where `event.agent` is in the set
///   - The special wildcard `"*"`: all events (admin / dashboard overview)
///
/// Subscription message format (JSON over the socket):
///   { "type": "subscribe", "agents": ["0xabc...", "0xdef..."] }
///   { "type": "subscribe", "agents": ["*"] }
///   { "type": "unsubscribe", "agents": ["0xabc..."] }
///   { "type": "unsubscribe", "agents": ["*"] }
///
/// Unauthenticated by design — the origin check on the WebSocket upgrade
/// (server.ts) is the auth boundary. Once connected, scoping is purely
/// about data relevance, not access control.

interface ManagedClient {
  socket: WebSocket;
  /// Set of agent addresses this client cares about. Empty = sees nothing.
  /// Contains "*" = sees everything.
  subscribedAgents: Set<string>;
}

const clients = new Map<WebSocket, ManagedClient>();

export function registerClient(socket: WebSocket) {
  const managed: ManagedClient = { socket, subscribedAgents: new Set() };
  clients.set(socket, managed);

  socket.on("message", (raw: Buffer | string) => {
    try {
      const msg = JSON.parse(raw.toString());
      if (msg.type === "subscribe" && Array.isArray(msg.agents)) {
        for (const a of msg.agents) {
          if (typeof a === "string") managed.subscribedAgents.add(a.toLowerCase());
        }
      } else if (msg.type === "unsubscribe" && Array.isArray(msg.agents)) {
        for (const a of msg.agents) {
          managed.subscribedAgents.delete(a.toLowerCase());
        }
      }
    } catch {
      // Malformed message — ignore, don't disconnect. The client might be
      // a health-check probe or a misconfigured consumer.
    }
  });

  socket.on("close", () => clients.delete(socket));
}

/// Broadcast an event to all clients subscribed to the given agent.
/// Clients with "*" in their subscription set always receive the event.
/// Clients with no matching subscription receive nothing.
export function broadcast(event: unknown) {
  const payload = JSON.stringify(event);
  // Extract the agent address from the event for scoping. Every indexer
  // event includes an `agent` field — payments, policies, allowlists, and
  // approval resolutions all name the agent. (approval_resolved resolves
  // the agent from the indexed PendingRequest row; in the rare case that
  // row is missing, the event degrades to the system-event path below.)
  const agent = extractAgent(event);
  if (agent === undefined) {
    // System events (auth_alert, etc.) go to wildcard subscribers only.
    sendToWildcard(payload);
    return;
  }
  const agentLower = agent.toLowerCase();
  for (const [, managed] of clients) {
    if (managed.socket.readyState !== managed.socket.OPEN) continue;
    if (managed.subscribedAgents.has("*") || managed.subscribedAgents.has(agentLower)) {
      managed.socket.send(payload);
    }
  }
}

function extractAgent(event: unknown): string | undefined {
  if (typeof event !== "object" || event === null) return undefined;
  const e = event as Record<string, unknown>;
  // All event types use "agent" as the field name.
  if (typeof e.agent === "string") return e.agent;
  return undefined;
}

function sendToWildcard(payload: string) {
  for (const [, managed] of clients) {
    if (managed.socket.readyState !== managed.socket.OPEN) continue;
    if (managed.subscribedAgents.has("*")) {
      managed.socket.send(payload);
    }
  }
}
