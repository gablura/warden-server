-- Add the events.agent FK (matches schema.prisma agentRef). Validated against
-- live data first: 0 orphan rows in this database (see migration session).
ALTER TABLE "events"
  ADD CONSTRAINT "events_agent_fkey"
  FOREIGN KEY ("agent") REFERENCES "agents"("address")
  ON DELETE RESTRICT ON UPDATE RESTRICT;
