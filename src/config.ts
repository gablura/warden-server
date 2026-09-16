import "dotenv/config";
import { z } from "zod";
import { isAddress } from "viem";

const address = z.string().refine((v) => isAddress(v), "invalid EVM address");

const schema = z.object({
  PORT: z.coerce.number().default(4000),
  CORS_ORIGIN: z.string().default("http://localhost:3000"),
  ARC_RPC_URL: z.string().url(),
  ARC_CHAIN_ID: z.coerce.number(),
  DATABASE_URL: z.string(),
  POLICY_REGISTRY_ADDRESS: address,
  SPEND_GUARD_ADDRESS: address,
  AUDIT_LOG_ADDRESS: address,
  ADMIN_PRIVATE_KEY: z.string().startsWith("0x"),
  APPROVER_PRIVATE_KEY: z.string().startsWith("0x"),

  // API keys for programmatic access (agents, bots).
  // These remain separate from Clerk — agents don't have Clerk accounts.
  WARDEN_API_KEYS: z.string().optional(),
  // Legacy keys — still accepted when WARDEN_API_KEYS is unset.
  ADMIN_API_KEY: z.string().min(32).optional(),
  APPROVER_API_KEY: z.string().min(32).optional(),

  // Clerk — human auth (Google OAuth, org management, roles).
  CLERK_SECRET_KEY: z.string().optional(),
  CLERK_WEBHOOK_SECRET: z.string().optional(),

  // Circle Wallets — embedded wallets for human users.
  CIRCLE_API_KEY: z.string().optional(),
  CIRCLE_ENTITY_SECRET: z.string().optional(),
  CIRCLE_WALLET_SET_ID: z.string().optional(),
  CIRCLE_BLOCKCHAIN: z.string().default("ETH-SEPOLIA"),
  CIRCLE_USDC_TOKEN_ID: z.string().optional(),

  // JWT signing — session tokens for authenticated humans.
  // Used when Clerk is not configured (fallback mode).
  JWT_SECRET: z.string().min(32).optional(),
}).superRefine((cfg, ctx) => {
  // Either API keys or Clerk must be present.
  const hasApiKeys = cfg.WARDEN_API_KEYS || (cfg.ADMIN_API_KEY && cfg.APPROVER_API_KEY);
  const hasClerk = !!cfg.CLERK_SECRET_KEY;

  if (!hasApiKeys && !hasClerk) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "set CLERK_SECRET_KEY (for human auth) or WARDEN_API_KEYS (for API key auth)",
      path: ["CLERK_SECRET_KEY"],
    });
  }

  // Circle Wallets — optional but must be complete if any field is set.
  const hasCircle = cfg.CIRCLE_API_KEY || cfg.CIRCLE_ENTITY_SECRET || cfg.CIRCLE_WALLET_SET_ID;
  if (hasCircle && (!cfg.CIRCLE_API_KEY || !cfg.CIRCLE_ENTITY_SECRET || !cfg.CIRCLE_WALLET_SET_ID)) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "CIRCLE_API_KEY, CIRCLE_ENTITY_SECRET, and CIRCLE_WALLET_SET_ID must all be set for embedded wallets",
      path: ["CIRCLE_API_KEY"],
    });
  }

  // JWT — required when Clerk is NOT configured (fallback mode).
  if (!hasClerk && !cfg.JWT_SECRET) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "JWT_SECRET is required when CLERK_SECRET_KEY is not set",
      path: ["JWT_SECRET"],
    });
  }
});

export const config = schema.parse(process.env);
