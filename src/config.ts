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
  // Legacy shared keys; still accepted, but superseded by WARDEN_API_KEYS
  // (named per-person credentials — see src/auth/credentials.ts). Optional
  // here so the legacy keys can be retired once the registry is in place.
  ADMIN_API_KEY: z.string().min(32, "ADMIN_API_KEY must be at least 32 characters").optional(),
  APPROVER_API_KEY: z.string().min(32, "APPROVER_API_KEY must be at least 32 characters").optional(),
  // Named API credentials, format (comma-separated): role:label:key[:maxApproval]
  // e.g. approver:alice:9f1c...:5000000000,admin:bob:ab12...
  // When set, these replace the legacy keys above entirely.
  WARDEN_API_KEYS: z.string().optional(),
}).superRefine((cfg, ctx) => {
  // Either auth source must be present — the server must never boot with
  // open admin/approver write routes.
  if (!cfg.WARDEN_API_KEYS && (!cfg.ADMIN_API_KEY || !cfg.APPROVER_API_KEY)) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "set WARDEN_API_KEYS (preferred) or both ADMIN_API_KEY and APPROVER_API_KEY",
      path: ["WARDEN_API_KEYS"],
    });
  }
});

// Throws with a readable message on boot if anything's missing —
// far better than a null-pointer three requests into production.
export const config = schema.parse(process.env);