import crypto from "node:crypto";
import { prisma } from "../db/client.js";
import { config } from "../config.js";

/// Optional HMAC request signing — replay protection for the api-key auth
/// layer. A raw `x-api-key` travels on every request and is valid forever if
/// intercepted (a logging pipeline, a misconfigured proxy). Signing makes a
/// captured request useless: each signature covers a timestamp, a fresh
/// nonce, and the exact body, and the server rejects anything stale or
/// already seen.
///
/// Wire format (all three headers must be present together, or all absent —
/// a partial set is an error, not a downgrade):
///   x-timestamp:  current unix time in ms, as a string
///   x-nonce:      at least 16 chars of randomness, unique per request
///   x-signature:  hex HMAC-SHA256(apiKey, `${timestamp}.${nonce}.${bodyHash}`)
///                 where bodyHash = sha256 hex of the exact raw request bytes
///                 (captured by the raw-body content-type parser in server.ts;
///                 sha256 of "" when there is no body, e.g. GET)
///
/// Enforcement is configuration-driven — no code change is needed to close
/// the migration window:
///   REQUIRE_SIGNED_REQUESTS=true            reject unsigned requests now
///   UNSIGNED_REQUESTS_ALLOWED_UNTIL=<ISO>   reject unsigned requests once
///                                           the deadline passes
/// Clients that send a partial header set, or fail verification, are always
/// rejected regardless of the window. See scripts/signed-request-example.mjs
/// for a reference signer.

const SIGNATURE_MAX_AGE_MS = 5 * 60 * 1000;
const MIN_NONCE_LENGTH = 16;

// Bounded replay-protection store. A nonce is remembered in the
// `signature_nonces` table for the whole freshness window, so a captured
// request can never be replayed while it would still validate. The store is
// the database (not per-process memory) because memory loses the window on
// every restart and is not shared across replicas — either gap would let a
// captured request be replayed. Rows are swept opportunistically (see
// sweepExpiredNonces), so the table stays roughly (requests per 5 min) big.

/// How often (per signed request) the expired-nonce sweep runs. Housekeeping
/// only — a skipped sweep leaves dead rows for the next one to collect.
const NONCE_SWEEP_PROBABILITY = 1 / 16;

function sha256Hex(input: string) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

export function expectedSignature(apiKey: string, timestamp: string, nonce: string, body: string) {
  return crypto.createHmac("sha256", apiKey).update(`${timestamp}.${nonce}.${sha256Hex(body)}`).digest("hex");
}

export type SignatureFailure =
  | { ok: true }
  | { ok: false; reason: "missing_timestamp" | "missing_nonce" | "missing_signature" | "bad_timestamp" | "stale_timestamp" | "bad_signature_format" | "replayed_nonce" | "invalid_signature" | "unsigned_request" };

/// Whether unsigned (legacy) api-key requests are still accepted. The
/// REQUIRE_SIGNED_REQUESTS flag forces enforcement immediately; otherwise
/// enforcement begins automatically once the migration deadline passes.
/// Evaluated per request (not cached at boot) so a scheduled deadline
/// cutover happens on time without a restart.
export function unsignedRequestsAllowed(): boolean {
  if (config.REQUIRE_SIGNED_REQUESTS) return false;
  if (config.UNSIGNED_REQUESTS_ALLOWED_UNTIL === undefined) return true;
  return Date.now() < Date.parse(config.UNSIGNED_REQUESTS_ALLOWED_UNTIL);
}

/// Records the nonce as consumed. Returns false when the nonce is already in
/// the table (a replay), true when this request owns it. The unique
/// constraint on `nonce` makes this race-safe across replicas: exactly one
/// concurrent request can claim a given nonce.
async function claimNonce(nonce: string, expiresAt: Date): Promise<boolean> {
  try {
    await prisma.signatureNonce.create({ data: { nonce, expiresAt } });
    return true;
  } catch (err) {
    if ((err as { code?: string }).code === "P2002") return false;
    throw err;
  }
}

/// Occasionally deletes rows whose freshness window has passed — they can
/// never be matched by a live request again. Fire-and-forget: sweeping is
/// housekeeping, and a failed sweep costs nothing but a retry next request.
function sweepExpiredNonces() {
  if (Math.random() >= NONCE_SWEEP_PROBABILITY) return;
  prisma.signatureNonce
    .deleteMany({ where: { expiresAt: { lt: new Date() } } })
    .catch(() => {});
}

export async function verifyRequestSignature(
  apiKey: string,
  headers: { timestamp?: string | string[]; nonce?: string | string[]; signature?: string | string[] },
  rawBody: string | undefined,
  options?: { allowUnsigned?: boolean },
): Promise<SignatureFailure> {
  const timestamp = typeof headers.timestamp === "string" ? headers.timestamp : undefined;
  const nonce = typeof headers.nonce === "string" ? headers.nonce : undefined;
  const signature = typeof headers.signature === "string" ? headers.signature : undefined;

  // Fully unsigned request → legacy mode. Accepted only while the configured
  // migration window is open (unsignedRequestsAllowed); once it closes, or
  // with REQUIRE_SIGNED_REQUESTS=true, this is a hard rejection.
  if (!timestamp && !nonce && !signature) {
    return options?.allowUnsigned === false ? { ok: false, reason: "unsigned_request" } : { ok: true };
  }
  if (!timestamp) return { ok: false, reason: "missing_timestamp" };
  if (!nonce) return { ok: false, reason: "missing_nonce" };
  if (!signature) return { ok: false, reason: "missing_signature" };

  const ts = Number(timestamp);
  if (!Number.isFinite(ts) || !Number.isInteger(ts)) return { ok: false, reason: "bad_timestamp" };
  const now = Date.now();
  if (Math.abs(now - ts) > SIGNATURE_MAX_AGE_MS) return { ok: false, reason: "stale_timestamp" };
  if (nonce.length < MIN_NONCE_LENGTH) return { ok: false, reason: "bad_signature_format" };

  // The signature covers the EXACT bytes on the wire (captured raw by the
  // content-type parser in server.ts), so any serialization difference
  // between client and server — key order, whitespace — is caught, and a
  // well-behaved client that signs the string it sends always verifies.
  const expected = expectedSignature(apiKey, timestamp, nonce, rawBody ?? "");
  const a = Buffer.from(signature, "hex");
  const b = Buffer.from(expected, "hex");
  // A malformed signature has the wrong byte length; comparing fixed-length
  // digests of both keeps timingSafeEqual's length precondition satisfied
  // without leaking where the mismatch is.
  const valid =
    a.length === b.length &&
    crypto.timingSafeEqual(crypto.createHash("sha256").update(a).digest(), crypto.createHash("sha256").update(b).digest());

  if (!valid) return { ok: false, reason: "invalid_signature" };

  // Burn the nonce only after the signature verifies — garbage signatures
  // must not consume a legitimately generated nonce. Claim failure here
  // means the nonce is already in the store: a replay.
  sweepExpiredNonces();
  const accepted = await claimNonce(nonce, new Date(now + SIGNATURE_MAX_AGE_MS));
  if (!accepted) return { ok: false, reason: "replayed_nonce" };

  return { ok: true };
}

// Fastify request augmentation — server.ts's raw-body content-type parser
// stores the untouched request bytes here so signature verification hashes
// exactly what the client sent.
declare module "fastify" {
  interface FastifyRequest {
    rawBody?: string;
  }
}
