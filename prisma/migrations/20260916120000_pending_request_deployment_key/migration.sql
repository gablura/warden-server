-- Per-org deployments: pending_requests is scoped by deployment.
--
-- Request ids are per-deployment on-chain counters (nextRequestId), so two
-- deployments can mint the same numeric id. The table's PK becomes
-- (deployment_key, request_id); existing rows predate multi-deployment and
-- all belong to the server's global deployment. The legacy single-column
-- indexes on (resolved) are dropped and rebuilt deployment-scoped.
--
-- Handles all four plausible pre-state variants (from earlier iterations of
-- this change): index may exist with/without a leading deployment_key column,
-- or not exist at all; PK may be table or name-based.

-- --- 1. tear down any single-column resolved indexes -----------------------
DROP INDEX IF EXISTS "pending_requests_resolved_idx";
DROP INDEX IF EXISTS "pending_requests_deployment_key_resolved_idx";

-- --- 2. rebuild the table around the composite key -------------------------
-- 2a. name-based PK (20260915032214_add_operator_actions era)
ALTER TABLE "pending_requests" DROP CONSTRAINT IF EXISTS "pending_requests_pkey";

-- 2b. table-shaped PK (20260914051900_init era)
ALTER TABLE "pending_requests" DROP CONSTRAINT IF EXISTS "pending_requests_request_id_key";

ALTER TABLE "pending_requests"
  ADD COLUMN IF NOT EXISTS "deployment_key" TEXT NOT NULL DEFAULT 'global',
  ADD CONSTRAINT "pending_requests_pkey" PRIMARY KEY ("deployment_key", "request_id");

-- --- 3. deployment-scoped query indexes ------------------------------------
CREATE INDEX IF NOT EXISTS "pending_requests_deployment_key_resolved_idx"
  ON "pending_requests" ("deployment_key", "resolved");
CREATE INDEX IF NOT EXISTS "pending_requests_deployment_key_resolved_created_at_idx"
  ON "pending_requests" ("deployment_key", "resolved", "created_at");
