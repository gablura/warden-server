import type { WebSocket } from "@fastify/websocket";
import { deploymentKey, type Deployment } from "../chain/orgContracts.js";
import { verifyWsTicket } from "./ticket.js";

/// Deployment-scoped WebSocket hub (hardening review §1 — unscoped /ws
/// broadcast; the multi-tenant follow-up).
///
/// Identity comes from a short-lived ticket verified at the upgrade
/// (ws/ticket.ts) — the origin check remains a separate, defense-in-depth
/// boundary. A connection's scope is fixed at handshake and decides what it
/// can ever see:
///   - global scope → every event from the global deployment (server-held
///     service credentials; org-scoped REST callers never receive this scope)
///   - org scope    → only events from that org's resolved deployment
///
/// Subscription is data relevance within a scope: specific agents, or "*"
/// for the scope's whole feed. Wildcards never cross scopes: an org-scoped
/// "*" subscriber sees every event of their org's deployment and nothing of
/// any other deployment — global deployments included.
///
/// Wire messages (JSON over the socket):
///   { "type": "subscribe",   "agents": ["0xabc...", "0xdef..."] }
///   { "type": "subscribe",   "agents": ["*"] }
///   { "type": "unsubscribe", "agents": ["0xabc..."] }
///
/// REST and WS scoping mirror each other by construction: the ticket's org
/// is resolved through the same resolveDeployment the routes use (item #2),
/// so a mainnet org sees exactly its deployment's feed, and testnet /
/// un-deployed orgs land on the global feed exactly like their REST calls.

interface ManagedClient {
  socket: WebSocket;
  /// Events are only delivered when this equals the event's deployment key.
  /// "global" names the env-configured deployment; an org id names that
  /// org's resolved deployment.
  scope: string;
  /// Set of agent addresses this client cares about. Empty = sees nothing.
  /// Contains "*" = sees the scope's whole feed.
  subscribedAgents: Set<string>;
}

const clients = new Map<WebSocket, ManagedClient>();

function attachSubscriptionHandling(managed: ManagedClient) {
  managed.socket.on("message", (raw: Buffer | string) => {
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

  managed.socket.on("close", () => clients.delete(managed.socket));
}

/// Authenticated handshake: verify the ticket, derive the scope server-side,
/// register the connection. Resolves false when the socket was rejected
/// (invalid or expired ticket). orgId → scope resolution is delegated so
/// this module stays free of DB and deployment-resolution dependencies
/// (server.ts passes resolveDeployment).
export async function registerClient(
  socket: WebSocket,
  ticket: string | undefined,
  resolveOrgScope: (orgId: string | null) => Promise<string>,
): Promise<boolean> {
  const claims = ticket ? verifyWsTicket(ticket) : null;
  if (!claims) {
    // Fail the handshake with the WS-standard policy-violation close code
    // before honoring any subscription: a client cannot upgrade to a feed
    // it cannot name.
    socket.close(1008, "invalid or missing ticket");
    return false;
  }

  const scope = await resolveOrgScope(claims.orgId);
  const managed: ManagedClient = { socket, scope, subscribedAgents: new Set() };
  clients.set(socket, managed);
  attachSubscriptionHandling(managed);
  return true;
}

/// Anonymous handshake — the pre-ticket behavior, kept ONLY for testnet
/// (one shared playground by design; see server.ts, which never calls this
/// on mainnet). The connection gets the global scope.
export function registerAnonymousClient(socket: WebSocket): void {
  const managed: ManagedClient = { socket, scope: "global", subscribedAgents: new Set() };
  clients.set(socket, managed);
  attachSubscriptionHandling(managed);
}

/// Deliver a live event to the deployment it belongs to. Callers pass the
/// deployment they emit from (watchPaymentEventsFor/watchPolicyEventsFor
/// know theirs; route emitters resolve the operator's deployment) so
/// delivery is scoped without agent→org DB lookups and without trusting
/// client subscriptions for isolation.
export function broadcastEvent(event: unknown, deployment: Deployment): void {
  const scope = deploymentKey(deployment);
  const payload = JSON.stringify(event);
  // Extract the agent address from the event for within-scope relevance
  // filtering. Every indexer event includes an `agent` field — payments,
  // policies, allowlists, and approval resolutions all name the agent.
  // (approval_resolved resolves the agent from the indexed PendingRequest
  // row; in the rare case that row is missing, the event degrades to the
  // scope-wide path below.)
  const agent = extractAgent(event);
  if (agent === undefined) {
    // Agentless events inside a scope go to the scope's wildcard subscribers.
    sendToScope(payload, scope);
    return;
  }
  const agentLower = agent.toLowerCase();
  for (const [, managed] of clients) {
    if (managed.scope !== scope) continue;
    if (managed.socket.readyState !== managed.socket.OPEN) continue;
    if (managed.subscribedAgents.has("*") || managed.subscribedAgents.has(agentLower)) {
      managed.socket.send(payload);
    }
  }
}

/// System-level events (auth-failure alerts, tx-failure alerts, boot
/// notices). These carry no tenant data and no infrastructure identifiers
/// (role name, reason — but never a source IP), so they reach wildcard
/// subscribers in every scope — every operator watches their own console.
export function broadcastSystem(event: unknown): void {
  const payload = JSON.stringify(event);
  for (const [, managed] of clients) {
    if (managed.socket.readyState !== managed.socket.OPEN) continue;
    if (managed.subscribedAgents.has("*")) {
      managed.socket.send(payload);
    }
  }
}

function sendToScope(payload: string, scope: string) {
  for (const [, managed] of clients) {
    if (managed.scope !== scope) continue;
    if (managed.socket.readyState !== managed.socket.OPEN) continue;
    if (managed.subscribedAgents.has("*")) {
      managed.socket.send(payload);
    }
  }
}

function extractAgent(event: unknown): string | undefined {
  if (typeof event !== "object" || event === null) return undefined;
  const e = event as Record<string, unknown>;
  if (typeof e.agent === "string" && e.agent.length > 0) return e.agent;
  return undefined;
}
