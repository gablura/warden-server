-- AlterTable
ALTER TABLE "pending_requests" ADD COLUMN     "expires_at" TIMESTAMP(3);

-- CreateIndex
CREATE INDEX "pending_requests_resolved_expires_at_idx" ON "pending_requests"("resolved", "expires_at");
