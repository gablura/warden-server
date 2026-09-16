// Offline self-test for the Circle execution module's verifiable core.
// Imports the REAL builders from src/chain/circleExecution.ts with stub env
// (config parses, no network touched) and proves:
//   1. the request body carries every field Circle requires,
//   2. encryptEntitySecret's RSA-OAEP-SHA256 output decrypts with Circle's
//      key form (PKCS#1 "RSA PUBLIC KEY" PEM) — i.e. the padding choice is
//      self-consistent and Node parses Circle's published key format,
//   3. malformed inputs fail loudly instead of producing bad requests.
//
// Run:  npx tsx scripts/circle-selftest.ts   (exit 0 = green)

// Stub env BEFORE config parses (must satisfy config.ts validation).
process.env.ARC_RPC_URL ??= "http://localhost:8545";
process.env.ARC_CHAIN_ID ??= "9999";
process.env.DATABASE_URL ??= "postgresql://u:p@localhost:5432/warden";
process.env.POLICY_REGISTRY_ADDRESS ??= "0x0000000000000000000000000000000000000001";
process.env.SPEND_GUARD_ADDRESS ??= "0x0000000000000000000000000000000000000002";
process.env.AUDIT_LOG_ADDRESS ??= "0x0000000000000000000000000000000000000003";
process.env.ADMIN_PRIVATE_KEY ??= "0x" + "11".repeat(32);
process.env.APPROVER_PRIVATE_KEY ??= "0x" + "22".repeat(32);
process.env.WARDEN_API_KEYS ??= `admin:tester:${"ab".repeat(32)}`;
process.env.JWT_SECRET ??= "ab".repeat(32);

import crypto from "node:crypto";
import assert from "node:assert/strict";
import { buildContractExecutionBody, encryptEntitySecret } from "../src/chain/circleExecution.js";

// --- 1. Body shape: every field Circle's contractExecution requires ---
const body = buildContractExecutionBody({
  walletId: "ce714f5b-0d8e-4062-9454-61aa1154869b",
  contractAddress: "0x0000000000000000000000000000000000000002",
  abiFunctionSignature: "approvePending(uint256)",
  abiParameters: ["123"],
  entitySecretCiphertext: "placeholder",
});
for (const f of [
  "idempotencyKey",
  "walletId",
  "contractAddress",
  "abiFunctionSignature",
  "abiParameters",
  "feeLevel",
  "entitySecretCiphertext",
] as const) {
  assert.ok(body[f] !== undefined && body[f] !== "", `missing required field ${f}`);
}
assert.match(body.idempotencyKey, /^[0-9a-f-]{36}$/, "idempotency key defaults to UUID");
assert.equal(body.feeLevel, "MEDIUM", "default fee level");
assert.deepEqual(body.abiParameters, ["123"]);
assert.throws(
  () =>
    buildContractExecutionBody({
      walletId: "",
      contractAddress: "0x0",
      abiFunctionSignature: "f()",
      abiParameters: [],
      entitySecretCiphertext: "x",
    }),
  /walletId is required/,
  "missing walletId fails loudly",
);
console.log("ok - contract execution body shape");

// --- 2. Real encryptEntitySecret round-trip in Circle's key form ---
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const pkcs1Pem = publicKey.export({ type: "pkcs1", format: "pem" }).toString();
assert.ok(pkcs1Pem.includes("RSA PUBLIC KEY"), "test key exported in Circle's PEM form");

const secretHex = crypto.randomBytes(32).toString("hex");
const b64 = encryptEntitySecret(pkcs1Pem, secretHex);
assert.ok(/^[A-Za-z0-9+/=]+$/.test(b64), "ciphertext is base64");
const recovered = crypto.privateDecrypt(
  { key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
  Buffer.from(b64, "base64"),
);
assert.equal(recovered.toString("hex"), secretHex, "Circle-form encryption round-trips under OAEP-SHA256");
assert.throws(() => encryptEntitySecret(pkcs1Pem, "not-a-secret"), /64 hex/, "malformed secret fails loudly");
assert.throws(() => encryptEntitySecret(pkcs1Pem, "abcd"), /64 hex/, "short secret fails loudly");
console.log("ok - encryptEntitySecret round-trip (RSA-OAEP-SHA256, PKCS#1 PEM)");

console.log("circle-selftest: all green");
