import { z } from "zod";
import { isAddress } from "viem";

// Shared request-body schemas for the /auth routes, grouped in one place so
// the shape of every auth mutation is visible at a glance.

export const createOrgBody = z.object({
  name: z.string().min(2).max(100),
}).strict();

export const inviteMemberBody = z.object({
  email: z.string().email(),
  role: z.enum(["admin", "approver", "viewer"]).default("viewer"),
}).strict();

export const updateMemberRoleBody = z.object({
  role: z.enum(["owner", "admin", "approver", "viewer"]),
}).strict();

// EVM addresses are case-insensitive; viem's isAddress accepts both cases,
// and we persist the exact string the user supplied.
const addressField = z.string().refine((v) => isAddress(v), "invalid EVM address");

export const externalWalletBody = z.object({
  // null unlinks the wallet; an EVM address links (or replaces) it.
  address: addressField.nullable(),
}).strict();

export const treasuryWalletBody = z.object({
  // null unlinks the treasury wallet; an EVM address links it.
  address: addressField.nullable(),
}).strict();

export const scopedTokenBody = z.object({
  orgId: z.string().min(1),
}).strict();
