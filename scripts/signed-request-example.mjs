#!/usr/bin/env node
/// Reference client for Warden's HMAC request signing (replay protection).
///
/// Run directly:
///   node scripts/signed-request-example.mjs
///
/// Or copy the `signedFetch` function into your service — it is deliberately
/// dependency-free (node:crypto only) and works against any route that
/// authenticates with an api key (x-api-key header or Bearer).
///
/// Wire format (all three headers are required together — a partial set is
/// rejected, never downgraded to unsigned):
///   x-timestamp:  current unix time in ms, as a string
///   x-nonce:      at least 16 chars of randomness, unique per request
///   x-signature:  hex HMAC-SHA256(apiKey, `${timestamp}.${nonce}.${bodyHash}`)
///                 where bodyHash = sha256 hex of the exact request body
///                 (JSON.stringify of the parsed body for JSON requests;
///                 sha256 of "" when there is no body, e.g. GET)
///
/// Server-side rules this must satisfy (see src/auth/requestSignature.ts):
///   - timestamps more than 5 minutes from the server's clock are rejected
///   - a nonce cannot be reused while its timestamp would still validate
///   - the signature covers the EXACT bytes on the wire (the server hashes
///     its raw-body capture) — sign the same string you send and do NOT let
///     an HTTP library re-serialize a passed object

import crypto from "node:crypto";

const DEFAULT_ORIGIN = process.env.WARDEN_API_URL ?? "http://localhost:4000";

function sha256Hex(input) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

/**
 * Fetch with Warden request signing headers.
 * @param {string} method HTTP method
 * @param {string} path e.g. "/approvals?limit=50"
 * @param {string} apiKey the api key (same value sent as x-api-key / Bearer)
 * @param {unknown} [body] JSON-serializable request body, or undefined for no body
 */
export async function signedFetch(method, path, apiKey, body) {
  const timestamp = Date.now().toString();
  // 32 hex chars of randomness — comfortably above the 16-char minimum.
  const nonce = crypto.randomBytes(16).toString("hex");

  // The signed string must be the exact bytes on the wire: what is signed
  // here is sent verbatim as the body, and the server hashes its raw-body
  // capture of those same bytes — key order and whitespace are preserved
  // end to end. For no body, sign "".
  const bodyString = body === undefined ? "" : JSON.stringify(body);
  const bodyHash = sha256Hex(bodyString);
  const signature = crypto.createHmac("sha256", apiKey).update(`${timestamp}.${nonce}.${bodyHash}`).digest("hex");

  const headers = {
    "content-type": "application/json",
    "x-api-key": apiKey,
    "x-timestamp": timestamp,
    "x-nonce": nonce,
    "x-signature": signature,
  };

  const res = await fetch(`${DEFAULT_ORIGIN}${path}`, {
    method,
    headers,
    ...(body === undefined ? {} : { body: bodyString }),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`${method} ${path} -> ${res.status} ${text}`);
  }
  return res.json();
}

// ── Demo when run directly ─────────────────────────────────────────────
const isMain = process.argv[1] && import.meta.url === `file://${process.argv[1].replace(/\\/g, "/")}`;
if (isMain) {
  const apiKey = process.env.WARDEN_API_KEY;
  if (!apiKey) {
    console.error("Set WARDEN_API_KEY (and optionally WARDEN_API_URL) and re-run.");
    process.exit(1);
  }

  console.log(`GET /auth/me →`, await signedFetch("GET", "/auth/me", apiKey));
}
