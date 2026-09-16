import crypto, { randomUUID } from "node:crypto";
import { config } from "../config.js";

// ── Circle contract execution (developer-controlled wallets) ─────────
//
// Submits a smart-contract call signed by a specific user's embedded wallet
// key (Circle holds the key, signs on our API call) — this is what makes an
// approval "a signature from that specific person's key" on-chain, rather
// than the shared relayer secret. Authorization still happens first in
// clerkAuth (scoped session → identity + role); Circle only ever sees an
// already-authorized intent.
//
// Verified against Circle's current API surface:
// - POST /v1/w3s/developer/transactions/contractExecution — required:
//   contractAddress, entitySecretCiphertext, idempotencyKey; walletId or
//   (walletAddress + blockchain); abiFunctionSignature + abiParameters;
//   feeLevel. Returns { data: { id, state } }.
// - GET /v1/w3s/developer/transactions/{id} → { data: { id, state, txHash } }.
// - Entity secret: 32 bytes (64 hex chars), encrypted per request with
//   Circle's RSA public key (RSA-OAEP, SHA-256 for OAEP hash and MGF1),
//   base64 output. Ciphertext is single-use — encrypted fresh for EVERY
//   call, never cached (only the public key is cached).
// - GET /v1/w3s/config/entity/publicKey → { data: { publicKey } }.
//
// Failure discipline: every Circle failure throws CircleError (typed with
// a retryable flag). Nothing here falls back to the relayer — routing is
// decided BEFORE submission (see signing.ts), so a Circle failure can never
// double-submit through another path.

const CIRCLE_W3S = "https://api.circle.com/v1/w3s";
const FEE_LEVEL = "MEDIUM";
const POLL_INTERVAL_MS = 3000;
const POLL_TIMEOUT_MS = 120_000;
const PUBKEY_TTL_MS = 60 * 60 * 1000;

export type CircleTxState =
  | "INITIATED"
  | "QUEUED"
  | "SENT"
  | "CONFIRMED"
  | "COMPLETE"
  | "FAILED"
  | "DENIED"
  | "CANCELLED";

const TERMINAL_FAILURE: ReadonlySet<string> = new Set(["FAILED", "DENIED", "CANCELLED"]);

export class CircleError extends Error {
  readonly retryable: boolean;
  readonly circleState?: string;
  constructor(message: string, opts?: { retryable?: boolean; circleState?: string; cause?: unknown }) {
    super(message, opts?.cause === undefined ? undefined : { cause: opts.cause });
    this.name = "CircleError";
    this.retryable = opts?.retryable ?? false;
    this.circleState = opts?.circleState;
  }
}

interface CircleApiError {
  message?: string;
  errors?: Array<{ message?: string; error?: string }>;
}

async function circleFetch(path: string, init: RequestInit): Promise<unknown> {
  let res: Response;
  try {
    res = await fetch(`${CIRCLE_W3S}${path}`, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${config.CIRCLE_API_KEY}`,
        ...(init.headers ?? {}),
      },
    });
  } catch (err) {
    throw new CircleError("Circle API unreachable", { retryable: true, cause: err });
  }

  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as CircleApiError;
    const detail = body.errors?.[0]?.message ?? body.errors?.[0]?.error ?? body.message ?? `HTTP ${res.status}`;
    // 429/5xx are retryable; 4xx (bad request, unknown wallet, bad chain)
    // will fail identically on retry.
    throw new CircleError(`Circle contract execution rejected: ${detail}`, {
      retryable: res.status === 429 || res.status >= 500,
    });
  }
  return res.json();
}

// ── Entity secret ────────────────────────────────────────────────────

let pubkeyCache: { key: string; fetchedAt: number } | null = null;

async function fetchEntityPublicKey(): Promise<string> {
  if (pubkeyCache && Date.now() - pubkeyCache.fetchedAt < PUBKEY_TTL_MS) {
    return pubkeyCache.key;
  }
  const json = (await circleFetch("/config/entity/publicKey", { method: "GET" })) as {
    data?: { publicKey?: string };
  };
  const publicKey = json.data?.publicKey;
  if (!publicKey) throw new CircleError("Circle entity public key missing from response", { retryable: true });
  pubkeyCache = { key: publicKey, fetchedAt: Date.now() };
  return publicKey;
}

/// Encrypt the entity secret with Circle's RSA public key (RSA-OAEP,
/// SHA-256 for both the OAEP hash and MGF1 — per Circle's sample code),
/// base64-encoded. Pure in (publicKeyPem, entitySecretHex) for testability.
export function encryptEntitySecret(publicKeyPem: string, entitySecretHex: string): string {
  if (!/^[0-9a-fA-F]{64}$/.test(entitySecretHex)) {
    throw new CircleError("CIRCLE_ENTITY_SECRET must be 32 bytes as 64 hex characters", { retryable: false });
  }
  const secret = Buffer.from(entitySecretHex, "hex");
  const encrypt = (pem: string) =>
    crypto.publicEncrypt(
      { key: pem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
      secret,
    );
  // Circle publishes the key as PKCS#1 ("RSA PUBLIC KEY"). Node parses that
  // directly; if a future rotation ships SPKI instead, the fallback covers it.
  try {
    return encrypt(publicKeyPem).toString("base64");
  } catch (first) {
    try {
      return encrypt(publicKeyPem.replace("RSA PUBLIC KEY", "PUBLIC KEY")).toString("base64");
    } catch {
      throw new CircleError("failed to encrypt entity secret with Circle public key", {
        retryable: false,
        cause: first,
      });
    }
  }
}

async function freshCiphertext(): Promise<string> {
  if (!config.CIRCLE_ENTITY_SECRET) {
    throw new CircleError("CIRCLE_ENTITY_SECRET is not configured", { retryable: false });
  }
  const publicKey = await fetchEntityPublicKey();
  return encryptEntitySecret(publicKey, config.CIRCLE_ENTITY_SECRET);
}

// ── Request building (pure — covered by the offline self-test) ───────

export interface ContractExecutionRequest {
  idempotencyKey: string;
  walletId: string;
  contractAddress: string;
  abiFunctionSignature: string;
  abiParameters: unknown[];
  feeLevel: string;
  entitySecretCiphertext: string;
}

export function buildContractExecutionBody(args: {
  walletId: string;
  contractAddress: string;
  abiFunctionSignature: string;
  abiParameters: unknown[];
  idempotencyKey?: string;
  feeLevel?: string;
  entitySecretCiphertext: string;
}): ContractExecutionRequest {
  if (!args.walletId) throw new CircleError("walletId is required for Circle execution", { retryable: false });
  if (!args.contractAddress) throw new CircleError("contractAddress is required", { retryable: false });
  return {
    idempotencyKey: args.idempotencyKey ?? randomUUID(),
    walletId: args.walletId,
    contractAddress: args.contractAddress,
    abiFunctionSignature: args.abiFunctionSignature,
    abiParameters: args.abiParameters,
    feeLevel: args.feeLevel ?? FEE_LEVEL,
    entitySecretCiphertext: args.entitySecretCiphertext,
  };
}

// ── Submit + wait ────────────────────────────────────────────────────

interface CircleTxResponse {
  data?: { id?: string; state?: string; txHash?: string };
}

/// Submit a contract execution from the user's wallet and wait for a
/// terminal state. Returns the on-chain tx hash. Throws CircleError on
/// rejection, on-chain failure, or timeout (a timeout does NOT mean the tx
/// died — the idempotency key makes a later retry safe to re-issue).
export async function executeContractAndWait(args: {
  walletId: string;
  contractAddress: string;
  abiFunctionSignature: string;
  abiParameters: unknown[];
  idempotencyKey?: string;
}): Promise<{ txHash: string; circleTxId: string }> {
  const ciphertext = await freshCiphertext();
  const body = buildContractExecutionBody({ ...args, entitySecretCiphertext: ciphertext });

  const created = (await circleFetch("/developer/transactions/contractExecution", {
    method: "POST",
    body: JSON.stringify(body),
  })) as CircleTxResponse;

  const circleTxId = created.data?.id;
  if (!circleTxId) throw new CircleError("Circle accepted the execution but returned no transaction id", { retryable: true });

  const deadline = Date.now() + POLL_TIMEOUT_MS;
  for (;;) {
    const current = (await circleFetch(`/developer/transactions/${circleTxId}`, { method: "GET" })) as CircleTxResponse;
    const state = current.data?.state as CircleTxState | undefined;

    if (state === "COMPLETE") {
      const txHash = current.data?.txHash;
      if (!txHash) throw new CircleError("Circle execution COMPLETE but returned no tx hash", { retryable: false });
      return { txHash, circleTxId };
    }
    if (state !== undefined && TERMINAL_FAILURE.has(state)) {
      // Most commonly an on-chain revert (e.g. caller not an approver).
      throw new CircleError(`Circle execution ended ${state}`, { retryable: false, circleState: state });
    }
    if (Date.now() > deadline) {
      throw new CircleError(
        `Circle execution ${circleTxId} did not complete within ${POLL_TIMEOUT_MS / 1000}s — retry with the same intent is idempotency-safe`,
        { retryable: true },
      );
    }
    await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
  }
}
