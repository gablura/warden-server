import { prisma } from "../db/client.js";
import { config } from "../config.js";

// Circle Programmable Wallets — embedded wallets for human users.
// Docs: https://developers.circle.com/wallets
//
// Wallet model:
// - One embedded wallet per person, provisioned automatically on first
//   login (see ensureUserWallet). `walletAddress`/`walletId` on the User
//   record are both unique and stay null until provisioning succeeds.
// - No seed phrase is ever shown to the user or stored by the server.
//   The user authorizes with their Circle PIN/passkey through the frontend
//   SDK; the server only ever persists the wallet id + address.
// - An organization may additionally link an external treasury
//   wallet/multisig (Fireblocks, Safe) via `Organization.treasuryWallet`,
//   and a user may link their own via `User.externalWalletAddress` —
//   both are validated add-ons, never replacements for the embedded wallet.
//
// Circle is optional infrastructure: when the CIRCLE_* env vars are absent,
// isCircleConfigured() is false and ensureUserWallet() resolves to null so
// login and every other flow keep working — the wallet is retried lazily
// on the next request that observes it missing.

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

const CIRCLE_BASE = "https://api.circle.com/v1";

async function circlePost<T>(
  path: string,
  body: Record<string, unknown>,
): Promise<T> {
  const res = await fetch(`${CIRCLE_BASE}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${config.CIRCLE_API_KEY}`,
    },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const err: CircleErrorResponse = await res.json().catch(() => ({}));
    const msg = err.errors?.[0]?.message ?? err.message ?? `Circle API ${res.status}`;
    throw new Error(`Circle wallet error: ${msg}`);
  }

  const json = await res.json() as { data: T };
  return json.data;
}

async function circleGet<T>(path: string): Promise<T> {
  const res = await fetch(`${CIRCLE_BASE}${path}`, {
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
export function isCircleConfigured(): boolean {
  return Boolean(config.CIRCLE_API_KEY && config.CIRCLE_ENTITY_SECRET && config.CIRCLE_WALLET_SET_ID);
}

/// Create a new wallet for a user. Idempotent — retries use a stable
/// idempotency key derived from the user id, so a retried request after a
/// network failure returns the already-created wallet instead of minting
/// a second one.
export async function createWallet(userId: string): Promise<CircleWalletResponse> {
  const walletSetId = config.CIRCLE_WALLET_SET_ID;
  if (!walletSetId) {
    throw new Error("Circle wallet set not configured");
  }

  const data = await circlePost<{ walletId: string; address: string; blockchain: string }>(
    "/wallets",
    {
      walletSetId,
      blockchain: config.CIRCLE_BLOCKCHAIN,
      metadata: { userId },
      idempotencyKey: `warden-user-${userId}`,
    },
  );

  return {
    walletId: data.walletId,
    address: data.address,
    blockchain: data.blockchain,
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
export async function ensureUserWallet(userId: string): Promise<CircleWalletResponse | null> {
  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user) return null;

  if (user.walletId && user.walletAddress) {
    return { walletId: user.walletId, address: user.walletAddress, blockchain: config.CIRCLE_BLOCKCHAIN };
  }

  if (!isCircleConfigured()) return null;

  const wallet = await createWallet(user.id);

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
}
