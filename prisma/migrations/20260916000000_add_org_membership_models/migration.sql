-- CreateEnum
-- org_role is not used as a Postgres enum since Prisma uses String for roles

-- AlterTable: Add organizationId to agents (nullable for backward compat)
ALTER TABLE "agents" ADD COLUMN "organization_id" TEXT;

-- CreateTable: organizations
CREATE TABLE "organizations" (
    "id" TEXT NOT NULL,
    "clerk_id" TEXT,
    "name" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "verified" BOOLEAN NOT NULL DEFAULT false,
    "mainnet_policy_registry" TEXT,
    "mainnet_spend_guard" TEXT,
    "mainnet_audit_log" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "organizations_pkey" PRIMARY KEY ("id")
);

-- CreateTable: memberships
CREATE TABLE "memberships" (
    "id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "organization_id" TEXT NOT NULL,
    "role" TEXT NOT NULL DEFAULT 'viewer',
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "memberships_pkey" PRIMARY KEY ("id")
);

-- CreateIndex: organizations
CREATE UNIQUE INDEX "organizations_clerk_id_key" ON "organizations"("clerk_id");
CREATE UNIQUE INDEX "organizations_slug_key" ON "organizations"("slug");

-- CreateIndex: memberships
CREATE UNIQUE INDEX "memberships_user_id_organization_id_key" ON "memberships"("user_id", "organization_id");

-- CreateIndex: agents
CREATE INDEX "agents_organization_id_idx" ON "agents"("organization_id");

-- AddForeignKey: agents -> organizations
ALTER TABLE "agents" ADD CONSTRAINT "agents_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey: memberships -> users
ALTER TABLE "memberships" ADD CONSTRAINT "memberships_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey: memberships -> organizations
ALTER TABLE "memberships" ADD CONSTRAINT "memberships_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;
