-- Correlation ID for end-to-end traceability (hardening review §5.1).
-- Nullable for backwards compatibility with existing rows.
ALTER TABLE "operator_actions" ADD COLUMN "correlation_id" TEXT;
CREATE INDEX "operator_actions_correlation_id_idx" ON "operator_actions"("correlation_id");
