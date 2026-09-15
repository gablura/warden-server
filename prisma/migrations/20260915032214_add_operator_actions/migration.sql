-- CreateTable
CREATE TABLE "operator_actions" (
    "id" SERIAL NOT NULL,
    "operator_id" TEXT NOT NULL,
    "operator_label" TEXT NOT NULL,
    "role" TEXT NOT NULL,
    "action" TEXT NOT NULL,
    "subject_id" TEXT NOT NULL,
    "tx_hash" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "operator_actions_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "operator_actions_created_at_idx" ON "operator_actions"("created_at");

-- CreateIndex
CREATE INDEX "operator_actions_operator_id_idx" ON "operator_actions"("operator_id");
