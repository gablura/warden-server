-- Session→API auth (§6) cleanup: drop the unused nonces table.
-- Request replay protection lives in the in-memory nonce cache in
-- src/auth/requestSignature.ts, not in the database — this table was never
-- read or written by any code path.
DROP TABLE "nonces";
