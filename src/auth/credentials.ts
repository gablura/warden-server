import crypto from "node:crypto";
import { z } from "zod";
import { config } from "../config.js";

/// Per-person API credentials, replacing the old two shared role keys.
///
/// Why: the whole product pitch is auditability, so "an approver approved
/// this" isn't good enough — the audit trail has to be able to name the
/// person behind the credential. Credentials are declared in env (see
/// .env.example) rather than the database so a leaked key is rotated by
/// redeploying config, not by writing to a table the server itself owns.
///
/// Format, one entry per credential, comma-separated:
///   role:label:key[:maxApproval]
/// e.g.  approver:alice:9f1c...:5000000000,admin:bob:ab12...
///
/// `maxApproval` (optional, approver role only) scopes that credential to
/// approvals at or below the given amount in on-chain base units. A shared
/// admin key that can approve anything any amount is the exact failure mode
/// the hardening review calls out; this makes scoping a property of the
/// credential instead of a convention.

export type Role = "admin" | "approver";

export interface Operator {
  /// Stable identifier used in audit rows — the label, lowercased.
  id: string;
  label: string;
  role: Role;
  /// Approval ceiling in base units, approver credentials only.
  /// undefined means unscoped.
  maxApproval?: bigint;
}

interface Credential extends Operator {
  keyHash: Buffer;
}

const credentialEntry = z
  .string()
  .transform((raw, ctx) => {
    const parts = raw.split(":");
    if (parts.length < 3 || parts.length > 4) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: `expected role:label:key[:maxApproval], got "${raw}"` });
      return z.NEVER;
    }
    const [role, label, key, maxApproval] = parts;
    if (role !== "admin" && role !== "approver") {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: `role must be "admin" or "approver", got "${role}"` });
      return z.NEVER;
    }
    if (label.length < 2) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: `label must be at least 2 characters, got "${label}"` });
      return z.NEVER;
    }
    if (key.length < 32) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: `key for "${label}" must be at least 32 characters` });
      return z.NEVER;
    }
    let ceiling: bigint | undefined;
    if (maxApproval !== undefined) {
      if (role !== "approver") {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: `maxApproval is only valid on approver credentials (${label})` });
        return z.NEVER;
      }
      try {
        ceiling = BigInt(maxApproval);
      } catch {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: `maxApproval for "${label}" is not an integer: "${maxApproval}"` });
        return z.NEVER;
      }
    }
    return { role: role as Role, label, key, maxApproval: ceiling };
  });

const credentialsSchema = z.array(credentialEntry).min(1, "at least one credential is required");

// Hashed once at boot, not per request. Same reasoning as before: comparing
// two fixed-length SHA-256 digests means timingSafeEqual never sees a length
// mismatch (which would leak the real key's length), and the expensive part
// happens once.
const toCredential = (entry: { role: Role; label: string; key: string; maxApproval?: bigint }): Credential => ({
  id: entry.label.toLowerCase(),
  label: entry.label,
  role: entry.role,
  maxApproval: entry.maxApproval,
  keyHash: crypto.createHash("sha256").update(entry.key).digest(),
});

function parseRegistry(): Credential[] {
  const entries: { role: Role; label: string; key: string; maxApproval?: bigint }[] = [];

  const declared = config.WARDEN_API_KEYS?.trim();
  if (declared) {
    const parsed = credentialsSchema.parse(declared.split(",").map((s) => s.trim()).filter(Boolean));
    entries.push(...parsed);
  } else {
    // Backward compatibility: the pre-registry ADMIN_API_KEY / APPROVER_API_KEY
    // keep working, attributed to "legacy" identities. Mark them clearly so
    // audit rows make it obvious the request came from a shared key, and so
    // the migration to named credentials is visible in the data.
    // superRefine in config.ts guarantees both legacy keys are present
    // whenever WARDEN_API_KEYS is unset, so these are safe.
    entries.push({ role: "admin", label: "legacy-admin", key: config.ADMIN_API_KEY! });
    entries.push({ role: "approver", label: "legacy-approver", key: config.APPROVER_API_KEY! });
  }

  const credentials = entries.map(toCredential);

  // Duplicate keys would silently make "who did this" ambiguous again, and
  // duplicate labels would make audit rows ambiguous — both are config
  // mistakes worth refusing to boot over.
  const seenKeys = new Set<string>();
  const seenIds = new Set<string>();
  for (const c of credentials) {
    const keyHex = c.keyHash.toString("hex");
    if (seenKeys.has(keyHex)) throw new Error(`duplicate api key detected (label "${c.label}") — every credential must have its own key`);
    seenKeys.add(keyHex);
    if (seenIds.has(c.id)) throw new Error(`duplicate credential label "${c.label}" — labels must be unique`);
    seenIds.add(c.id);
  }

  return credentials;
}

export const credentials = parseRegistry();

export function findCredential(role: Role, providedKey: string): Operator | undefined {
  const providedHash = crypto.createHash("sha256").update(providedKey).digest();
  const match = credentials.find(
    (c) => c.role === role && crypto.timingSafeEqual(providedHash, c.keyHash),
  );
  // Return the public Operator view only — never leak the hash.
  return match ? { id: match.id, label: match.label, role: match.role, maxApproval: match.maxApproval } : undefined;
}

/// Fastify request augmentation — downstream handlers read `req.operator`
/// to attribute the action to a person instead of a role.
declare module "fastify" {
  interface FastifyRequest {
    operator?: Operator;
  }
}
