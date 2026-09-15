-- Composite index for /audit?agent=X&limit=N and /agents/:address?limit=N
-- Covers: WHERE agent = ? ORDER BY timestamp DESC LIMIT ?
CREATE INDEX "events_agent_timestamp_idx" ON "events"("agent", "timestamp");

-- Composite index for /approvals?limit=N
-- Covers: WHERE resolved = false ORDER BY createdAt ASC LIMIT ?
CREATE INDEX "pending_requests_resolved_created_at_idx" ON "pending_requests"("resolved", "created_at");

-- Composite index for cursor-based keyset pagination on events
-- Covers: WHERE (timestamp, id) < (?, ?) ORDER BY timestamp DESC, id DESC
CREATE INDEX "events_timestamp_id_idx" ON "events"("timestamp", "id");
