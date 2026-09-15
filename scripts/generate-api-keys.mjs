#!/usr/bin/env node
/// Generates per-person API credentials and prints a ready-to-paste
/// WARDEN_API_KEYS value for .env — so adding N users never means hand-
/// writing N entries.
///
/// Usage:
///   node scripts/generate-api-keys.mjs alice:approver:1000000000 bob:admin carol:approver
///   node scripts/generate-api-keys.mjs --file users.txt
///
/// Each entry is  label:role[:maxApproval]  (maxApproval in base units,
/// USDC = 6 decimals, approvers only). Output:
///   - the WARDEN_API_KEYS=... line for .env
///   - a private distribution table (one row per person: label, key) —
///     hand each person ONLY their own row.
///
/// Keys are 32 random bytes, hex-encoded. They are printed once and are
/// not stored anywhere by this script — save the output if you need it.

import crypto from "node:crypto";
import { readFileSync } from "node:fs";

function usage() {
  console.error(`Usage:
  node scripts/generate-api-keys.mjs alice:approver:1000000000 bob:admin carol:approver
  node scripts/generate-api-keys.mjs --file users.txt   (one label:role[:maxApproval] per line)`);
  process.exit(1);
}

const args = process.argv.slice(2);
let entries = [];

if (args[0] === "--file") {
  if (!args[1]) usage();
  entries = readFileSync(args[1], "utf8")
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith("#"));
} else {
  entries = args;
}

if (entries.length === 0) usage();

const credentials = [];
for (const entry of entries) {
  const [label, role, maxApproval] = entry.split(":");
  if (!label || !role) {
    console.error(`invalid entry "${entry}" — expected label:role[:maxApproval]`);
    process.exit(1);
  }
  if (role !== "admin" && role !== "approver") {
    console.error(`invalid role "${role}" for "${label}" — must be admin or approver`);
    process.exit(1);
  }
  if (maxApproval && role !== "approver") {
    console.error(`maxApproval is only valid on approver credentials ("${label}")`);
    process.exit(1);
  }
  credentials.push({ label, role, maxApproval, key: crypto.randomBytes(32).toString("hex") });
}

// The server rejects duplicate keys/labels at boot; catch the (vanishingly
// unlikely) key collision here so the printed line is always boot-safe.
const keys = new Set(credentials.map((c) => c.key));
if (keys.size !== credentials.length) {
  console.error("key collision while generating — rerun");
  process.exit(1);
}

const value = credentials
  .map((c) => `${c.role}:${c.label}:${c.key}${c.maxApproval ? `:${c.maxApproval}` : ""}`)
  .join(",");

console.log("— add this single line to .env —\n");
console.log(`WARDEN_API_KEYS=${value}`);
console.log("\n— distribution (share each person ONLY their own row) —");
console.log("label       role        key");
for (const c of credentials) {
  console.log(`${c.label.padEnd(11)} ${c.role.padEnd(11)} ${c.key}`);
}
console.log("\nKeys are shown once; store them in your secrets manager before closing this terminal.");
