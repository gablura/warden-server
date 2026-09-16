-- Audit signer identity (§2/§6): record the actual on-chain msg.sender and
-- how it signed for every operator action. Nullable so existing rows stay
-- valid — they predate per-person signing and keep their person-level
-- attribution (operator_id/label/wallet_address).
ALTER TABLE "operator_actions" ADD COLUMN "signer_address" TEXT;
ALTER TABLE "operator_actions" ADD COLUMN "signing_via" TEXT;
