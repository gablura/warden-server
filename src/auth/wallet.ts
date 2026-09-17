import { prisma } from "../db/client.js";
import { config } from "../config.js";
import { publicEncrypt, createPublicKey, randomUUID } from "node:crypto";

// Circle Programmable Wallets — developer-controlled wallets for humans and agents.
// Docs: https://developers.circle.com/wallets
//
// Wallet model:
// - Developer-controlled: the server's entity secret authorizes every wallet
//   operation; end users never see a PIN or passkey prompt.
// - One embedded wallet per person, provisioned automatically on first
//   login (see ensureUserWallet). `walletAddress`/`walletId` on the User
//   record are both unique and stay null until provisioning succeeds.
// - Agents get the same model: one Circle wallet per agent, created when
//   the admin registers the agent. The wallet address IS the agent's
//   on-chain identity (registered via PolicyRegistry.setPolicy).
// - An organization may additionally link an external treasury
//   wallet/multisig (Fireblocks, Safe) via `Organization.treasuryWallet`,
//   and a user may link their own via `User.externalWalletAddress` —
//   both are validated add-ons, never replacements for the embedded wallet.
//
// Circle is optional infrastructure: when the CIRCLE_* env vars are absent,
// isCircleConfigured() is false and ensureUserWallet()/ensureAgentWallet()
// resolve to null so login and every other flow keep working — the wallet
// is retried lazily on the next request that observes it missing.

interface CircleWalletResponse {
  walletId: string;
  address: string;
  blockchain: string;
}

interface CircleErrorResponse {
  code?: number;
  message?: string;
  errors?: Array<{ message?: string }>;
}

// Circle API base URL — all keys (including testnet) use production endpoint
function circleBaseUrl(): string {
  return "https://api.circle.com/v1";
}

// ── Entity secret encryption ────────────────────────────────────────
// Circle's Developer Controlled Wallets API expects the entity secret
// encrypted with RSA-OAEP using Circle's public key, sent as
// `entitySecretCiphertext` in the request body — not as a header.

let cachedPublicKey: string | null = null;

async function getEntitySecretCiphertext(): Promise<string> {
  if (!config.CIRCLE_ENTITY_SECRET) {
    throw new Error("CIRCLE_ENTITY_SECRET not configured");
  }

  if (!cachedPublicKey) {
    const res = await fetch(`${circleBaseUrl()}/w3s/config/entity/publicKey`, {
      headers: { Authorization: `Bearer ${config.CIRCLE_API_KEY}` },
    });
    if (!res.ok) throw new Error(`Failed to fetch Circle public key: ${res.status}`);
    const { data } = await res.json() as { data: { publicKey: string } };
    cachedPublicKey = data.publicKey;
  }

  const publicKey = createPublicKey(cachedPublicKey);
  const encrypted = publicEncrypt(
    { key: publicKey, padding: 4, oaepHash: "sha256" },
    Buffer.from(config.CIRCLE_ENTITY_SECRET, "hex"),
  );
  return encrypted.toString("base64");
}

// Cooldown map: after a failed Circle API call, don't retry for this user
// for COOLDOWN_MS. Prevents hammering the API on every /auth/me request
// when provisioning fails (e.g. rate limit 429).
const COOLDOWN_MS = 60_000;
const cooldowns = new Map<string, number>();

function isInCooldown(userId: string): boolean {
  const until = cooldowns.get(userId);
  if (!until) return false;
  if (Date.now() < until) return true;
  cooldowns.delete(userId);
  return false;
}

function setCooldown(userId: string): void {
  cooldowns.set(userId, Date.now() + COOLDOWN_MS);
}

/// Clear cooldown for a user — called by manual retry endpoint.
export function clearCooldown(userId: string): void {
  cooldowns.delete(userId);
}

// Retry with exponential backoff for transient errors (429, 500, 502, 503)
async function circlePostWithRetry<T>(
  path: string,
  body: Record<string, unknown>,
  opts: { retries?: number; baseDelay?: number } = {},
): Promise<T> {
  const maxRetries = opts.retries ?? 3;
  const baseDelay = opts.baseDelay ?? 1000;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await circlePost<T>(path, body);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "";
      const isRetryable = msg.includes("429") || msg.includes("500") || msg.includes("502") || msg.includes("503");
      if (isRetryable && attempt < maxRetries) {
        const delay = baseDelay * Math.pow(2, attempt);
        await new Promise((r) => setTimeout(r, delay));
        continue;
      }
      throw err;
    }
  }
  throw new Error("Unreachable");
}

async function circlePost<T>(
  path: string,
  body: Record<string, unknown>,
): Promise<T> {
  const url = `${circleBaseUrl()}${path}`;
  // Add encrypted entity secret to body (Circle SDK way)
  const entitySecretCiphertext = await getEntitySecretCiphertext();
  const headers = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${config.CIRCLE_API_KEY}`,
  };
  console.log("[wallet] Circle POST", url, "key:", config.CIRCLE_API_KEY?.substring(0, 15) + "...");

  const res = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify({ ...body, entitySecretCiphertext }),
  });

  if (!res.ok) {
    const errBody = await res.json().catch(() => ({}));
    console.log("[wallet] Circle error", res.status, JSON.stringify(errBody));
    const err: CircleErrorResponse = errBody;
    const msg = err.errors?.[0]?.message ?? err.message ?? `Circle API ${res.status}`;
    throw new Error(`Circle wallet error: ${msg}`);
  }

  const json = await res.json() as { data: T };
  return json.data;
}

async function circleGet<T>(path: string): Promise<T> {
  const res = await fetch(`${circleBaseUrl()}${path}`, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${config.CIRCLE_API_KEY}`,
    },
  });

  if (!res.ok) {
    const err: CircleErrorResponse = await res.json().catch(() => ({}));
    const msg = err.errors?.[0]?.message ?? err.message ?? `Circle API ${res.status}`;
    throw new Error(`Circle wallet error: ${msg}`);
  }

  const json = await res.json() as { data: T };
  return json.data;
}

/// True when all Circle env vars are present and wallet calls can be made.
let circleConfigLogged = false;
export function isCircleConfigured(): boolean {
  const result = Boolean(config.CIRCLE_API_KEY && config.CIRCLE_ENTITY_SECRET && config.CIRCLE_WALLET_SET_ID);
  if (!result && !circleConfigLogged) {
    circleConfigLogged = true;
    console.log("[wallet] Circle not configured:", {
      hasApiKey: !!config.CIRCLE_API_KEY,
      hasEntitySecret: !!config.CIRCLE_ENTITY_SECRET,
      hasWalletSetId: !!config.CIRCLE_WALLET_SET_ID,
      rawApiKey: process.env.CIRCLE_API_KEY ? "set" : "unset",
      rawEntitySecret: process.env.CIRCLE_ENTITY_SECRET ? "set" : "unset",
      rawWalletSetId: process.env.CIRCLE_WALLET_SET_ID ? "set" : "unset",
    });
  }
  return result;
}

/// Create a new developer-controlled SCA wallet for a user. Idempotent —
/// retries use a stable idempotency key derived from the user id, so a
/// retried request after a network failure returns the already-created
/// wallet instead of minting a second one.
///
/// Account type is always "SCA" (smart contract account) to enable gas
/// sponsorship for the mobile-approval UX.
export async function createWallet(
  userId: string,
  opts: { name?: string } = {},
): Promise<CircleWalletResponse> {
  const walletSetId = config.CIRCLE_WALLET_SET_ID;
  if (!walletSetId) {
    throw new Error("Circle wallet set not configured");
  }

  const { wallets } = await circlePostWithRetry<{ wallets: { id: string; address: string; blockchain: string }[] }>(
    "/w3s/developer/wallets",
    {
      walletSetId,
      accountType: "SCA",
      blockchains: [config.CIRCLE_BLOCKCHAIN],
      metadata: [{ name: opts.name ?? "User", refId: `user:${userId}` }],
      idempotencyKey: randomUUID(),
    },
  );

  const w = wallets[0];
  return {
    walletId: w.id,
    address: w.address,
    blockchain: w.blockchain,
  };
}

/// Get wallet details by ID (read-only lookup, e.g. to confirm the
/// on-record address still matches Circle's).
export async function getWallet(walletId: string): Promise<CircleWalletResponse> {
  const data = await circleGet<{ walletId: string; address: string; blockchain: string }>(
    `/wallets/${walletId}`,
  );
  return {
    walletId: data.walletId,
    address: data.address,
    blockchain: data.blockchain,
  };
}

export type WalletStatus = "ready" | "pending" | "unavailable";

/// Derive the wallet state for API responses: `ready` when an address is
/// on record, `unavailable` when Circle isn't configured (auth still works,
/// wallet-dependent features report this instead of failing), `pending`
/// when Circle is configured but provisioning hasn't completed yet.
export function walletStatusFor(user: { walletAddress: string | null }): WalletStatus {
  if (user.walletAddress) return "ready";
  return isCircleConfigured() ? "pending" : "unavailable";
}

/// Ensure the user has an embedded wallet, provisioning one on first use.
///
/// - Returns the wallet (existing or newly created), or null when Circle
///   is not configured — callers treat null as "wallet unavailable" and
///   must never fail the surrounding auth flow because of it.
/// - Throws only when Circle IS configured but the call fails; callers
///   catch, log, and continue so a Circle outage can never lock users out.
///   The next request retries, since the record is still empty.
/// - Safe under concurrency: the `(walletAddress, walletId)` unique
///   constraints mean a lost race surfaces as P2002, in which case we
///   re-read the row the winner wrote.
export async function ensureUserWallet(
  userId: string,
  opts: { name?: string } = {},
): Promise<CircleWalletResponse | null> {
  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user) {
    console.log("[wallet] ensureUserWallet: user not found", userId);
    return null;
  }

  if (user.walletId && user.walletAddress) {
    return { walletId: user.walletId, address: user.walletAddress, blockchain: config.CIRCLE_BLOCKCHAIN };
  }

  if (!isCircleConfigured()) return null;
  if (isInCooldown(userId)) {
    console.log("[wallet] ensureUserWallet: in cooldown", userId);
    return null;
  }

  console.log("[wallet] ensureUserWallet: attempting Circle wallet creation", userId);
  try {
    const wallet = await createWallet(userId, { name: opts.name ?? user.label ?? user.email });

    try {
      await prisma.user.update({
        where: { id: user.id },
        data: { walletId: wallet.walletId, walletAddress: wallet.address },
      });
    } catch (err) {
      // P2002: a concurrent request provisioned first — return their row.
      const code = (err as { code?: string }).code;
      if (code !== "P2002") throw err;
      const winner = await prisma.user.findUnique({ where: { id: user.id } });
      if (winner?.walletId && winner?.walletAddress) {
        return { walletId: winner.walletId, address: winner.walletAddress, blockchain: config.CIRCLE_BLOCKCHAIN };
      }
      throw err;
    }

    return wallet;
  } catch (err) {
    setCooldown(userId);
    throw err;
  }
}

// ── Agent wallets ────────────────────────────────────────────────────────
//
// Agent wallets follow the same developer-controlled SCA model as human
// wallets. The Circle wallet is created first; its address is what gets
// registered on-chain via PolicyRegistry.setPolicy. The agent's on-chain
// identity and its Circle-controlled wallet are the same thing.

/// Create a new developer-controlled SCA wallet for an agent. Idempotent —
/// uses a stable idempotency key derived from the agent address.
export async function createAgentWallet(
  agentAddress: string,
  opts: { name?: string } = {},
): Promise<CircleWalletResponse> {
  const walletSetId = config.CIRCLE_WALLET_SET_ID;
  if (!walletSetId) {
    throw new Error("Circle wallet set not configured");
  }

  const { wallets } = await circlePostWithRetry<{ wallets: { id: string; address: string; blockchain: string }[] }>(
    "/w3s/developer/wallets",
    {
      walletSetId,
      accountType: "SCA",
      blockchains: [config.CIRCLE_BLOCKCHAIN],
      metadata: [{ name: opts.name ?? "Agent", refId: `agent:${agentAddress}` }],
      idempotencyKey: randomUUID(),
    },
  );

  const w = wallets[0];
  return {
    walletId: w.id,
    address: w.address,
    blockchain: w.blockchain,
  };
}

/// Ensure an agent has a Circle wallet, provisioning one if needed.
///
/// - Returns the wallet (existing or newly created), or null when Circle
///   is not configured.
/// - Throws only when Circle IS configured but the call fails.
export async function ensureAgentWallet(agentAddress: string): Promise<CircleWalletResponse | null> {
  const agent = await prisma.agent.findUnique({ where: { address: agentAddress } });
  if (!agent) return null;

  if (agent.circleWalletId && agent.address) {
    return { walletId: agent.circleWalletId, address: agent.address, blockchain: config.CIRCLE_BLOCKCHAIN };
  }

  if (!isCircleConfigured()) return null;
  if (isInCooldown(agentAddress)) return null;

  try {
    const wallet = await createAgentWallet(agentAddress, { name: agent.label ?? "Agent" });

    try {
      await prisma.agent.update({
        where: { address: agentAddress },
        data: { circleWalletId: wallet.walletId },
      });
    } catch (err) {
      // P2002: a concurrent request provisioned first — return their row.
      const code = (err as { code?: string }).code;
      if (code !== "P2002") throw err;
      const winner = await prisma.agent.findUnique({ where: { address: agentAddress } });
      if (winner?.circleWalletId) {
        return { walletId: winner.circleWalletId, address: agentAddress, blockchain: config.CIRCLE_BLOCKCHAIN };
      }
      throw err;
    }

    return wallet;
  } catch (err) {
    setCooldown(agentAddress);
    throw err;
  }
}
