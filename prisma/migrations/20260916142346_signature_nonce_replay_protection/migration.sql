-- CreateTable
CREATE TABLE "signature_nonces" (
    "nonce" TEXT NOT NULL,
    "expires_at" TIMESTAMP(3) NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "signature_nonces_pkey" PRIMARY KEY ("nonce")
);

-- CreateIndex
CREATE INDEX "signature_nonces_expires_at_idx" ON "signature_nonces"("expires_at");
