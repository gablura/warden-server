import type { FastifyInstance } from "fastify";
import type { Agent } from "@prisma/client";
import { z } from "zod";
import { prisma, serializeBigInts } from "../db/client.js";
import { readAgentPolicies, readAgentPolicy, type AgentPolicySnapshot } from "../chain/policyState.js";
import { submitAsAdmin } from "../chain/signing.js";
import { resolveDeployment, resolveDeploymentForAgent, deploymentKey } from "../chain/orgContracts.js";
import { requireRole, optionalAuth } from "../auth/clerkAuth.js";
import { productionGate } from "../auth/productionGate.js";
import { ensureAgentWallet, isCircleConfigured } from "../auth/wallet.js";
import { getCorrelationId } from "../auth/correlation.js";
import { limitQuerySchema, paginatedQuery, cursorQuerySchema, cursorPaginatedQuery, cursorWhere, encodeCursor } from "../db/pagination.js";

/// The agent set visible to a caller: the agents of the caller's resolved
/// deployment — their org's own contracts on mainnet, the shared global
/// deployment on testnet and for service/anonymous callers (the exact scope
/// rule /approvals uses). Agents are org-stamped by the indexers (see
/// watchPolicyEvents / watchPaymentEvents), so the membership filter is
/// exact; `organizationId: null` matches the unstamped global-deployment
/// agents.
async function scopedAgentWhere(orgId: string | null | undefined) {
  const deployment = await resolveDeployment(orgId ?? null);
  return deployment.orgId === null ? { organizationId: null } : { organizationId: deployment.orgId };
}

// EVM addresses are case-insensitive; checksum casing is a display convention.
// The indexer stores the lowercase form it gets from the event args, so
// normalizing here keeps a checksummed URL from missing its own agent row.
const normalizeAddress = (address: string) => address.toLowerCase();

/// Caps and spend come from PolicyRegistry, not the indexed row.
///
/// `agents.spent_today` is incremented by the event indexer and never rolled
/// over at the UTC day boundary, so the stored column is wrong from midnight
/// until that agent's next payment of the day — exactly the window an operator
/// is most likely to be looking at it. The live read is the source of truth,
/// so these fields are overwritten rather than merged, and `policySource` makes
/// that explicit for clients. Label, status, and timestamps are pure dashboard
/// metadata and stay DB-sourced.
function withLivePolicy(agent: Agent, policy: AgentPolicySnapshot) {
  return {
    ...agent,
    dailyCap: policy.dailyCap,
    perTxCap: policy.perTxCap,
    escalationThreshold: policy.escalationThreshold,
    spentToday: policy.spentToday,
    // Escalation reservations (day-aware): headroom queued requests are
    // holding, and when the newest one expires (informational).
    activeReserved: policy.activeReserved,
    reservedUntil: policy.reservedUntil,
    // Cap headroom AFTER spend and live reservations.
    remainingToday: policy.remainingToday,
    lastResetDay: policy.lastResetDay,
    currentDay: policy.currentDay,
    // False means the registry has never seen this address, so the row is
    // historical and every policy value above is zero by definition.
    policyExists: policy.exists,
    policySource: "chain" as const,
    blockNumber: policy.blockNumber,
  };
}

export async function agentRoutes(app: FastifyInstance) {
  app.get<{ Querystring: { limit?: string } }>("/agents", { preHandler: optionalAuth() }, async (req) => {
    const { limit } = limitQuerySchema.parse(req.query);

    const result = await paginatedQuery(
      async (take) => prisma.agent.findMany({ where: await scopedAgentWhere(req.operator?.orgId), take }),
      limit,
    );

    const policies = await readAgentPolicies(result.data.map((agent) => normalizeAddress(agent.address)));

    const enriched = result.data.map((agent, index) => {
      const policy = withLivePolicy(agent, policies[index]!);
      // "Near cap" counts COMMITTED headroom — spend plus live escalation
      // reservations — since a queued escalation is exactly the kind of
      // imminent spend the flag exists to surface.
      const committed = policy.spentToday + policy.activeReserved;
      const spentPct = policy.dailyCap > 0n ? Number((committed * 100n) / policy.dailyCap) : 0;
      return { ...policy, nearCap: spentPct >= 80 };
    });

    // Sorted on live spend — the old `orderBy: { spentToday: "desc" }` sorted on
    // a column this route no longer trusts.
    enriched.sort((a, b) => (b.spentToday > a.spentToday ? 1 : b.spentToday < a.spentToday ? -1 : 0));

    return serializeBigInts({ data: enriched, hasMore: result.hasMore });
  });

  app.get<{ Params: { address: string }; Querystring: { limit?: string; cursor?: string } }>("/agents/:address", { preHandler: optionalAuth() }, async (req, reply) => {
    const address = normalizeAddress(req.params.address);

    const agent = await prisma.agent.findUnique({ where: { address } });
    if (!agent) return reply.code(404).send({ error: "agent not found" });

    // Same deployment scope as the list: an agent belonging to another
    // org's deployment is indistinguishable from a missing one — 404, never
    // 403, which would leak its existence.
    const callerKey = deploymentKey(await resolveDeployment(req.operator?.orgId ?? null));
    const agentKey = deploymentKey(await resolveDeployment(agent.organizationId));
    if (callerKey !== agentKey) return reply.code(404).send({ error: "agent not found" });

    // Fail-closed: if the chain read rejects, the whole request 503s (see the
    // error handler in server.ts) rather than answering with indexed values.
    const [policy, recentPayments] = await Promise.all([
      readAgentPolicy(address),
      cursorPaginatedQuery(
        (take, cursor) =>
          prisma.event.findMany({
            where: { agent: address, ...(cursor ? cursorWhere(cursor, "desc") : {}) },
            orderBy: [{ timestamp: "desc" }, { id: "desc" }],
            take,
          }),
        req.query,
      ),
    ]);

    const last = recentPayments.data[recentPayments.data.length - 1];
    return serializeBigInts({
      agent: withLivePolicy(agent, policy),
      recentPayments: {
        ...recentPayments,
        nextCursor: recentPayments.hasMore && last ? encodeCursor(last.id, last.timestamp) : null,
      },
    });
  });

  // ── Register a new agent ──────────────────────────────────────────────
  //
  // Admin creates an agent by providing metadata only — no address.
  // The backend:
  //   1. Creates a Circle SCA wallet (the address becomes the agent's identity)
  //   2. Registers the policy on-chain via PolicyRegistry.setPolicy
  //   3. Stores the wallet ID and address on the agent row
  //
  // The Circle wallet is always created FIRST; its address is what gets
  // registered on-chain. Never register an on-chain role for an address
  // that doesn't already have a matching Circle-controlled wallet.

  const registerAgentBody = z.object({
    label: z.string().min(1).max(100).optional(),
    dailyCap: z.coerce.bigint(),
    perTxCap: z.coerce.bigint(),
    escalationThreshold: z.coerce.bigint(),
  }).strict().refine(
    (data) => data.perTxCap <= data.dailyCap,
    { message: "perTxCap must be <= dailyCap" },
  ).refine(
    (data) => data.escalationThreshold <= data.perTxCap,
    { message: "escalationThreshold must be <= perTxCap" },
  );

  app.post("/agents", {
    preHandler: [requireRole("admin"), productionGate()],
    config: { rateLimit: { max: 10, timeWindow: "1 minute" } },
  }, async (req, reply) => {
    if (!req.operator) return reply.code(500).send({ error: "internal_error", message: "operator identity missing" });

    const body = registerAgentBody.parse(req.body);

    // Step 1: Create Circle wallet first (SCA, developer-controlled)
    if (!isCircleConfigured()) {
      return reply.code(503).send({
        error: "wallet_unavailable",
        message: "Circle wallet infrastructure not configured",
      });
    }

    // Use a temporary address as idempotency key placeholder — the real
    // address comes from Circle. If Circle is called twice with the same
    // label+operator, the idempotency key prevents duplicate wallets.
    const tempId = `pending-${req.operator.id}-${Date.now()}`;
    let wallet;
    try {
      const { createAgentWallet } = await import("../auth/wallet.js");
      wallet = await createAgentWallet(tempId, { name: body.label ?? "Agent" });
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Circle wallet creation failed";
      return reply.code(502).send({ error: "wallet_creation_failed", message: msg });
    }

    // The wallet address is the agent's on-chain identity
    const agentAddress = wallet.address.toLowerCase();

    // Step 2: Register policy on-chain
    const deployment = await resolveDeploymentForAgent(agentAddress);
    req.log.info({ agentAddress, dailyCap: body.dailyCap.toString(), perTxCap: body.perTxCap.toString(), escalationThreshold: body.escalationThreshold.toString() }, "Calling setPolicy on-chain");
    let signing;
    try {
      signing = await submitAsAdmin(deployment, "policyRegistry", "setPolicy", [
        agentAddress as `0x${string}`,
        body.dailyCap,
        body.perTxCap,
        body.escalationThreshold,
      ]);
    } catch (err) {
      // On-chain registration failed — wallet exists but agent isn't
      // registered. The wallet is orphaned but harmless; the admin can
      // retry with the same label to get the same wallet (idempotent).
      req.log.error({ err, agentAddress, deployment: deployment.orgId ?? "global" }, "setPolicy on-chain registration failed");
      const msg = err instanceof Error ? err.message : "On-chain registration failed";
      return reply.code(502).send({ error: "chain_registration_failed", message: msg });
    }

    // Step 3: Store agent in DB with wallet info
    const agent = await prisma.agent.create({
      data: {
        address: agentAddress,
        label: body.label,
        dailyCap: body.dailyCap,
        perTxCap: body.perTxCap,
        escalationThreshold: body.escalationThreshold,
        organizationId: deployment.orgId,
        circleWalletId: wallet.walletId,
      },
    });

    // Record operator action for audit trail
    await prisma.operatorAction.create({
      data: {
        operatorId: req.operator.id,
        operatorLabel: req.operator.label,
        role: req.operator.role,
        action: "register_agent",
        subjectId: agentAddress,
        txHash: signing.txHash,
        correlationId: getCorrelationId() ?? null,
        walletAddress: req.operator.walletAddress ?? null,
        signerAddress: signing.signer,
        signingVia: signing.via,
      },
    });

    return reply.code(201).send({
      address: agent.address,
      label: agent.label,
      dailyCap: agent.dailyCap.toString(),
      perTxCap: agent.perTxCap.toString(),
      escalationThreshold: agent.escalationThreshold.toString(),
      txHash: signing.txHash,
      signer: signing.signer,
      via: signing.via,
      correlationId: req.correlationId,
    });
  });
}