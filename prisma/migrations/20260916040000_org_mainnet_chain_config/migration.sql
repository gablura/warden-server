-- Per-org mainnet deployments (§7): an org's own chain endpoint completes
-- its mainnet contract addresses. All five columns are one unit — the
-- resolver only uses an org deployment when every one is set.
ALTER TABLE "organizations" ADD COLUMN "mainnet_rpc_url" TEXT;
ALTER TABLE "organizations" ADD COLUMN "mainnet_chain_id" INTEGER;
