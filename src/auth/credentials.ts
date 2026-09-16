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
///   role:label:key[:previousKey][:maxApproval]
/// e.g.  approver:alice:9f1c...:5000000000,admin:bob:ab12...
///
/// Rotation: when rotating a key, set `previousKey` to the old key. Both
/// the current key and previousKey are accepted during the rotation window.
/// Remove previousKey once all clients have migrated to the new key. This
/// gives a grace period where old and new keys both work — no hard cutover,
/// no midnight redeploy races.
///
/// `maxApproval` (optional, approver role only) scopes that credential to
/// approvals at or below the given amount in on-chain base units.

export type Role = "admin" | "approver";

export interface Operator {
  /// Stable identifier used in audit rows — the label, lowercased.
  id: string;
  label: string;
  role: string;
  /// Approval ceiling in base units, approver credentials only.
  /// undefined means unscoped.
  maxApproval?: bigint;
  /// Organization context (Clerk users only).
  orgId?: string;
  orgRole?: string;
  walletAddress?: string;
}

interface Credential extends Operator {
  keyHash: Buffer;
  /// Previous key hash, present during rotation window. When set, both
  /// the current key and the previous key are accepted. Removed from
  /// config once all clients have migrated to the new key.
  previousKeyHash?: Buffer;
}

const credentialEntry = z
  .string()
  .transform((raw, ctx) => {
    const parts = raw.split(":");
    if (parts.length < 3 || parts.length > 5) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: `expected role:label:key[:previousKey][:maxApproval], got "${raw}"` });
      return z.NEVER;
    }
    const [role, label, key] = parts;
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

    // Parse optional trailing segments. The last segment is maxApproval
    // if it's a valid BigInt; otherwise it's previousKey.
    let previousKey: string | undefined;
    let maxApproval: bigint | undefined;

    const trailing = parts.slice(3);
    if (trailing.length === 2) {
      // role:label:key:previousKey:maxApproval
      previousKey = trailing[0];
      try { maxApproval = BigInt(trailing[1]); } catch {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: `maxApproval for "${label}" is not an integer: "${trailing[1]}"` });
        return z.NEVER;
      }
    } else if (trailing.length === 1) {
      // Disambiguate: role:label:key:maxApproval vs role:label:key:previousKey
      try {
        maxApproval = BigInt(trailing[0]);
      } catch {
        // Not a BigInt → treat as previousKey
        previousKey = trailing[0];
      }
    }

    if (maxApproval !== undefined && role !== "approver") {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: `maxApproval is only valid on approver credentials (${label})` });
      return z.NEVER;
    }
    if (previousKey !== undefined && previousKey.length < 32) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: `previousKey for "${label}" must be at least 32 characters` });
      return z.NEVER;
    }

    return { role: role as Role, label, key, previousKey, maxApproval };
  });

const credentialsSchema = z.array(credentialEntry).min(1, "at least one credential is required");

// Hashed once at boot, not per request. Same reasoning as before: comparing
// two fixed-length SHA-256 digests means timingSafeEqual never sees a length
// mismatch (which would leak the real key's length), and the expensive part
// happens once.
const toCredential = (entry: { role: Role; label: string; key: string; previousKey?: string; maxApproval?: bigint }): Credential => ({
  id: entry.label.toLowerCase(),
  label: entry.label,
  role: entry.role,
  maxApproval: entry.maxApproval,
  keyHash: crypto.createHash("sha256").update(entry.key).digest(),
  previousKeyHash: entry.previousKey ? crypto.createHash("sha256").update(entry.previousKey).digest() : undefined,
});

function parseRegistry(): Credential[] {
  const entries: { role: Role; label: string; key: string; previousKey?: string; maxApproval?: bigint }[] = [];

  // Clerk-only deploys set no API keys at all — service auth is then
  // simply absent (every human authenticates via Clerk/scoped tokens).
  const declared = config.WARDEN_API_KEYS?.trim();
  if (declared) {
    const parsed = credentialsSchema.parse(declared.split(",").map((s) => s.trim()).filter(Boolean));
    entries.push(...parsed);
  }

  const credentials = entries.map(toCredential);

  // Duplicate keys would silently make "who did this" ambiguous again, and
  // duplicate labels would make audit rows ambiguous — both are config
  // mistakes worth refusing to boot over.
  //
  // A previousKey is allowed to match its own credential's current key
  // (that would be pointless but not ambiguous). But a previousKey must
  // not match any *other* credential's current or previous key — that
  // would mean two identities share a secret.
  const currentKeys = new Map<string, string>(); // keyHex → label (for error messages)
  const previousKeys = new Map<string, string>();
  const seenIds = new Set<string>();
  for (const c of credentials) {
    const currentHex = c.keyHash.toString("hex");
    const existingCurrent = currentKeys.get(currentHex);
    if (existingCurrent) throw new Error(`duplicate api key detected (label "${c.label}" same key as "${existingCurrent}") — every credential must have its own key`);
    const existingPrevious = previousKeys.get(currentHex);
    if (existingPrevious) throw new Error(`duplicate api key detected (label "${c.label}" current key is another credential's previous key "${existingPrevious}") — rotate to a unique key`);
    currentKeys.set(currentHex, c.label);

    if (c.previousKeyHash) {
      const prevHex = c.previousKeyHash.toString("hex");
      // Previous key matching its own current key is pointless but allowed.
      // Previous key matching another credential's key is not allowed.
      if (prevHex !== currentHex) {
        const existingAsCurrent = currentKeys.get(prevHex);
        if (existingAsCurrent) throw new Error(`duplicate api key detected (label "${c.label}" previous key is "${existingAsCurrent}"'s current key) — rotate to a unique key`);
        const existingAsPrevious = previousKeys.get(prevHex);
        if (existingAsPrevious) throw new Error(`duplicate api key detected (label "${c.label}" previous key matches "${existingAsPrevious}"'s previous key) — each rotation must use a fresh key`);
        previousKeys.set(prevHex, c.label);
      }
    }

    if (seenIds.has(c.id)) throw new Error(`duplicate credential label "${c.label}" — labels must be unique`);
    seenIds.add(c.id);
  }

  return credentials;
}

export const credentials = parseRegistry();

export function findCredential(role: Role, providedKey: string): Operator | undefined {
  const providedHash = crypto.createHash("sha256").update(providedKey).digest();
  const match = credentials.find(
    (c) => c.role === role && (
      crypto.timingSafeEqual(providedHash, c.keyHash) ||
      (c.previousKeyHash !== undefined && crypto.timingSafeEqual(providedHash, c.previousKeyHash))
    ),
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
