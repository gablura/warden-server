-- CreateTable
CREATE TABLE "agents" (
    "address" TEXT NOT NULL,
    "label" TEXT,
    "daily_cap" BIGINT NOT NULL,
    "per_tx_cap" BIGINT NOT NULL,
    "escalation_threshold" BIGINT NOT NULL,
    "spent_today" BIGINT NOT NULL DEFAULT 0,
    "status" TEXT NOT NULL DEFAULT 'active',
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "agents_pkey" PRIMARY KEY ("address")
);

-- CreateTable
CREATE TABLE "events" (
    "id" SERIAL NOT NULL,
    "agent" TEXT NOT NULL,
    "counterparty" TEXT NOT NULL,
    "amount" BIGINT NOT NULL,
    "decision" TEXT NOT NULL,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "tx_hash" TEXT NOT NULL,

    CONSTRAINT "events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "pending_requests" (
    "request_id" BIGINT NOT NULL,
    "agent" TEXT NOT NULL,
    "counterparty" TEXT NOT NULL,
    "amount" BIGINT NOT NULL,
    "resolved" BOOLEAN NOT NULL DEFAULT false,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "pending_requests_pkey" PRIMARY KEY ("request_id")
);

-- CreateTable
CREATE TABLE "allowlist" (
    "agent" TEXT NOT NULL,
    "counterparty" TEXT NOT NULL,
    "allowed" BOOLEAN NOT NULL,

    CONSTRAINT "allowlist_pkey" PRIMARY KEY ("agent","counterparty")
);

-- CreateIndex
CREATE INDEX "events_agent_idx" ON "events"("agent");

-- CreateIndex
CREATE INDEX "events_timestamp_idx" ON "events"("timestamp");

-- CreateIndex
CREATE INDEX "pending_requests_resolved_idx" ON "pending_requests"("resolved");
