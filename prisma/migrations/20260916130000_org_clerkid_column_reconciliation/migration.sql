-- Reconcile the organizations table with the Prisma schema (same drift class
-- the users table hit earlier: a hand-written migration created a snake_case
-- column the schema never mapped). Every Clerk-authenticated query touching
-- organizations failed with P2022 "column organizations.clerkId does not
-- exist", surfacing as a 500 on org creation.
--
-- Every statement below is guarded on the live state: with driver adapters
-- Prisma applies migrations statement-by-statement (autocommit), so an
-- interrupted run can leave the DB partially migrated — this script must
-- converge from ANY intermediate state, including fully applied.

-- 1. organizations.clerk_id -> clerkId (schema field has no @map, so Prisma
--    expects the camelCase column).
DO $$ BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'organizations' AND column_name = 'clerk_id'
  ) THEN
    ALTER TABLE "organizations" RENAME COLUMN "clerk_id" TO "clerkId";
  END IF;
END $$;

DO $$ BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_indexes
    WHERE tablename = 'organizations' AND indexname = 'organizations_clerk_id_key'
  ) THEN
    ALTER INDEX "organizations_clerk_id_key" RENAME TO "organizations_clerkId_key";
  END IF;
END $$;

-- 2. Schema declares clerkId NOT NULL. Legacy rows predating Clerk may hold
--    NULL — stamp a deterministic placeholder (own id) before constraining.
--    (Backfill must be an UPDATE: Postgres forbids column references in
--    DEFAULT expressions.)
DO $$ BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'organizations' AND column_name = 'clerkId' AND is_nullable = 'YES'
  ) THEN
    UPDATE "organizations" SET "clerkId" = 'legacy_' || "id" WHERE "clerkId" IS NULL;
    ALTER TABLE "organizations" ALTER COLUMN "clerkId" SET NOT NULL;
  END IF;
END $$;

-- 3. Legacy users.role / users.isProductionAccess: the app no longer reads
--    them (roles live on Memberships since 20260916000000).
DO $$ BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'users' AND column_name = 'role'
  ) THEN
    ALTER TABLE "users" DROP COLUMN "role";
  END IF;
END $$;

DO $$ BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'users' AND column_name = 'isProductionAccess'
  ) THEN
    ALTER TABLE "users" DROP COLUMN "isProductionAccess";
  END IF;
END $$;

-- 4. pending_requests (resolved, created_at): superseded by the deployment-
--    scoped indexes from 20260916120000_pending_request_deployment_key. No
--    query uses the unscoped shape (all reads filter by deployment_key first).
DO $$ BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_indexes
    WHERE tablename = 'pending_requests' AND indexname = 'pending_requests_resolved_created_at_idx'
  ) THEN
    DROP INDEX "pending_requests_resolved_created_at_idx";
  END IF;
END $$;

-- agents_organization_id_idx is NOT dropped: the schema now declares
-- @@index([organizationId]) on Agent, whose default name is exactly
-- agents_organization_id_idx — declaring it resolves that drift, dropping
-- it would recreate it.
