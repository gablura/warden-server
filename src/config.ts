import "dotenv/config";
import { z } from "zod";
import { isAddress } from "viem";

const address = z.string().refine((v) => isAddress(v), "invalid EVM address");

// ISO 8601 datetime (e.g. 2026-10-01T00:00:00Z), tolerating the empty string
// dotenv produces for an unset `KEY=` line in a copied .env.example (treated
// as absent). Parsed at boot so a typo fails fast instead of silently never
// expiring at runtime.
const isoDatetime = z
  .string()
  .transform((v) => (v.trim() === "" ? undefined : v))
  .refine((v): v is string | undefined => v === undefined || !Number.isNaN(Date.parse(v)), "must be an ISO 8601 datetime (e.g. 2026-10-01T00:00:00Z)");

// 0x-prefixed 20-byte private key (exactly 64 hex chars). "startsWith(0x)"
// accepted any trailing junk and failed only later, deep in viem at first
// use — validating the full shape here fails fast at boot instead.
const privateKey = z
  .string()
  .regex(/^0x[0-9a-fA-F]{64}$/, "must be a 0x-prefixed 32-byte hex string (64 hex chars)");

const schema = z.object({
  PORT: z.coerce.number().default(4000),
  CORS_ORIGIN: z.string().default("http://localhost:3000"),
  ARC_RPC_URL: z.string().url(),
  // Optional ordered backup RPC endpoints (hardening review §5.5, incident
  // scenario 3 previously said "switch to a backup RPC endpoint by updating
  // ARC_RPC_URL and redeploying" — with fallbacks that failover is
  // automatic). Parsed as a comma-separated list; every entry must be a
  // valid URL. Leave unset for the single-endpoint behavior.
  ARC_RPC_FALLBACK_URLS: z
    .string()
    .transform((v) => (v.trim() === "" ? [] : v.split(",").map((s) => s.trim()).filter(Boolean)))
    .refine(
      (urls) => urls.every((u) => {
        try { new URL(u); return true; } catch { return false; }
      }),
      "every fallback must be a valid URL",
    )
    .refine((urls) => new Set(urls).size === urls.length, "fallback URLs must not repeat")
    .refine((urls) => !urls.includes(process.env.ARC_RPC_URL ?? ""), "fallbacks must not repeat ARC_RPC_URL")
    .optional(),
  ARC_CHAIN_ID: z.coerce.number(),
  DATABASE_URL: z.string(),
  POLICY_REGISTRY_ADDRESS: address,
  SPEND_GUARD_ADDRESS: address,
  AUDIT_LOG_ADDRESS: address,
  ADMIN_PRIVATE_KEY: privateKey,
  APPROVER_PRIVATE_KEY: privateKey,

  // API keys for programmatic access (service callers without Clerk
  // accounts). Per-credential identity (role:label:key, see credentials.ts)
  // — the old shared ADMIN/APPROVER_API_KEY pair was removed as part of the
  // session→API auth migration (§6): shared static secrets no longer exist.
  WARDEN_API_KEYS: z.string().optional(),

  // HMAC request signing (replay protection, see auth/requestSignature.ts).
  // REQUIRE_SIGNED_REQUESTS rejects unsigned api-key requests immediately —
  // flip it once every service caller signs (see
  // scripts/signed-request-example.mjs).
  // UNSIGNED_REQUESTS_ALLOWED_UNTIL is the migration deadline: unsigned
  // requests are accepted until it passes, then rejected automatically. At
  // least one must be set — without either, the signing scheme exists but
  // can never be enforced, which the review called out as a gap.
  REQUIRE_SIGNED_REQUESTS: z
    .enum(["true", "false"])
    .default("false")
    .transform((v) => v === "true"),
  UNSIGNED_REQUESTS_ALLOWED_UNTIL: isoDatetime.optional(),

  // Network the server's contracts live on. Testnet is ungated by design
  // (exploration); on mainnet the production gate requires verified orgs.
  WARDEN_NETWORK: z.enum(["testnet", "mainnet"]).default("testnet"),

  // Clerk — human auth (Google OAuth, org management, roles).
  CLERK_SECRET_KEY: z.string().optional(),
  CLERK_WEBHOOK_SECRET: z.string().optional(),

  // Circle Wallets — embedded wallets for human users.
  CIRCLE_API_KEY: z.string().optional(),
  CIRCLE_ENTITY_SECRET: z.string().optional(),
  CIRCLE_WALLET_SET_ID: z.string().optional(),
  CIRCLE_BLOCKCHAIN: z.string().default("ETH-SEPOLIA"),
  CIRCLE_USDC_TOKEN_ID: z.string().optional(),

  // JWT signing — scoped session tokens (POST /auth/token, §6).
  // Always required: even Clerk-only deploys mint short-lived org-scoped
  // tokens from Clerk sessions, so the signing key must exist at boot.
  JWT_SECRET: z.string().min(32),
}).superRefine((cfg, ctx) => {
  // Either API keys or Clerk must be present.
  const hasApiKeys = !!cfg.WARDEN_API_KEYS;
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

  // Request-signing enforcement must be meaningful: a deadline in the past
  // without the flag is fine (it just enforces), but a deadline in the PAST
  // set alongside the flag is redundant, and one in the past is always a
  // misconfiguration worth refusing at boot — deadlines are for scheduling
  // a future cutover, not for documenting one that already happened.
  if (cfg.UNSIGNED_REQUESTS_ALLOWED_UNTIL !== undefined && Date.parse(cfg.UNSIGNED_REQUESTS_ALLOWED_UNTIL) <= Date.now()) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "UNSIGNED_REQUESTS_ALLOWED_UNTIL is in the past — set REQUIRE_SIGNED_REQUESTS=true instead",
      path: ["UNSIGNED_REQUESTS_ALLOWED_UNTIL"],
    });
  }

});

export const config = schema.parse(process.env);
