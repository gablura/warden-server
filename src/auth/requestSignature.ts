import crypto from "node:crypto";
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
///                 where bodyHash = sha256 hex of the exact request body
///                 (JSON.stringify of the parsed body for JSON requests;
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
const NONCE_TTL_MS = SIGNATURE_MAX_AGE_MS;
const MIN_NONCE_LENGTH = 16;

// Bounded in-memory replay cache. A nonce is remembered for slightly longer
// than the freshness window, so a captured request can never be replayed
// within the window it would still validate. Size is naturally bounded by
// (requests per 5 min) — for the volume this server sees, a Map with
// opportunistic sweeping is the right tool, not a dependency.
const seenNonces = new Map<string, number>();

function sweepNonces(now: number) {
  if (seenNonces.size < 10_000) return;
  for (const [nonce, expiry] of seenNonces) {
    if (expiry <= now) seenNonces.delete(nonce);
  }
}

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

export function verifyRequestSignature(
  apiKey: string,
  headers: { timestamp?: string | string[]; nonce?: string | string[]; signature?: string | string[] },
  body: unknown,
  options?: { allowUnsigned?: boolean },
): SignatureFailure {
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

  sweepNonces(now);
  const nonceExpiry = seenNonces.get(nonce);
  if (nonceExpiry !== undefined && nonceExpiry > now) return { ok: false, reason: "replayed_nonce" };

  // Key order matters: the client must sign the exact serialized body it
  // sends (JSON.stringify of their object), because the server hashes
  // JSON.stringify of what it parsed — identical when the client does the
  // same, which is the documented contract.
  const bodyString = body === undefined || body === null ? "" : JSON.stringify(body);
  const expected = expectedSignature(apiKey, timestamp, nonce, bodyString);
  const a = Buffer.from(signature, "hex");
  const b = Buffer.from(expected, "hex");
  // A malformed signature has the wrong byte length; comparing fixed-length
  // digests of both keeps timingSafeEqual's length precondition satisfied
  // without leaking where the mismatch is.
  const valid =
    a.length === b.length &&
    crypto.timingSafeEqual(crypto.createHash("sha256").update(a).digest(), crypto.createHash("sha256").update(b).digest());

  if (!valid) return { ok: false, reason: "invalid_signature" };

  // Only burn the nonce on success — otherwise garbage signatures could
  // poison a legitimately generated nonce.
  seenNonces.set(nonce, now + NONCE_TTL_MS);
  return { ok: true };
}
