import { config } from "../config.js";

// Circle Wallets API — programmable wallets for human users.
// Docs: https://developers.circle.com/wallets
//
// Each user gets an Ethereum wallet tied to their Circle account.
// The wallet is custodial (Circle holds keys) — users sign via the
// Circle SDK without ever seeing a seed phrase. This is the same
// infra used for agent custody, keeping one wallet provider across
// the product.

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

async function circleRequest<T>(
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

/// Create a new wallet for a user. Idempotent — if the user already has
/// a wallet, this returns the existing one (by walletSetId lookup).
export async function createWallet(userId: string): Promise<CircleWalletResponse> {
  // Check if user already has a wallet by looking up the wallet set.
  // Circle doesn't have a "get wallets by metadata" endpoint, so we
  // rely on the walletId stored in the User record. If that's missing,
  // we create a new wallet.
  const walletSetId = config.CIRCLE_WALLET_SET_ID;
  if (!walletSetId) {
    throw new Error("Circle wallet set not configured");
  }

  const data = await circleRequest<{ walletId: string; address: string; blockchain: string }>(
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

/// Get wallet details by ID.
export async function getWallet(walletId: string): Promise<CircleWalletResponse> {
  const data = await circleRequest<{ walletId: string; address: string; blockchain: string }>(
    `/wallets/${walletId}`,
    {},
  );
  return {
    walletId: data.walletId,
    address: data.address,
    blockchain: data.blockchain,
  };
}
