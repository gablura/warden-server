-- Wallet layer completion: per-user external wallet, org treasury wallet,
-- wallet address on audit rows, and persistent token-based invitations.

-- AlterTable: users get an optional linked external wallet/multisig.
-- Deliberately NOT unique: a shared Safe can be linked by several people,
-- unlike the embedded wallet which stays one-per-person.
ALTER TABLE "users" ADD COLUMN "external_wallet_address" TEXT;

-- AlterTable: organizations get an optional treasury wallet/multisig add-on.
ALTER TABLE "organizations" ADD COLUMN "treasury_wallet" TEXT;

-- AlterTable: audit rows name the specific person's key when known.
ALTER TABLE "operator_actions" ADD COLUMN "wallet_address" TEXT;

-- CreateTable: invitations (token-based org invites, Clerk-independent).
CREATE TABLE "invitations" (
    "id" TEXT NOT NULL,
    "organization_id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "role" TEXT NOT NULL DEFAULT 'viewer',
    "token" TEXT NOT NULL,
    "expires_at" TIMESTAMP(3) NOT NULL,
    "accepted_at" TIMESTAMP(3),
    "created_by" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "invitations_pkey" PRIMARY KEY ("id")
);

-- CreateIndex: invitations
CREATE UNIQUE INDEX "invitations_token_key" ON "invitations"("token");
CREATE INDEX "invitations_organization_id_idx" ON "invitations"("organization_id");
CREATE INDEX "invitations_email_idx" ON "invitations"("email");

-- AddForeignKey: invitations -> organizations
ALTER TABLE "invitations" ADD CONSTRAINT "invitations_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;
