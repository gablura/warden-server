import "dotenv/config";
import { z } from "zod";

const schema = z.object({
  PORT: z.coerce.number().default(4000),
  CORS_ORIGIN: z.string().default("http://localhost:3000"),
  ARC_RPC_URL: z.string().url(),
  ARC_CHAIN_ID: z.coerce.number(),
  DATABASE_URL: z.string(),
  POLICY_REGISTRY_ADDRESS: z.string().startsWith("0x"),
  SPEND_GUARD_ADDRESS: z.string().startsWith("0x"),
  AUDIT_LOG_ADDRESS: z.string().startsWith("0x"),
  ADMIN_PRIVATE_KEY: z.string().startsWith("0x"),
  APPROVER_PRIVATE_KEY: z.string().startsWith("0x"),
  // Separate from the chain keys above — these gate who's allowed to
  // *ask* the server to sign an admin/approver transaction at all.
  ADMIN_API_KEY: z.string().min(32, "ADMIN_API_KEY must be at least 32 characters"),
  APPROVER_API_KEY: z.string().min(32, "APPROVER_API_KEY must be at least 32 characters"),
});

// Throws with a readable message on boot if anything's missing —
// far better than a null-pointer three requests into production.
export const config = schema.parse(process.env);