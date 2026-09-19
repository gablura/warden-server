import type { FastifyInstance } from "fastify";
import { authMeRoutes } from "./me.js";
import { authOrgRoutes } from "./orgs.js";
import { authInviteRoutes } from "./invites.js";
import { authMemberRoutes } from "./members.js";

// Aggregates the /auth route modules into the single plugin server.ts
// registers. Each module owns one domain:
//
//   me.ts       → profile, wallets, scoped tokens, ws tickets
//   orgs.ts     → organization lifecycle + treasury wallet
//   invites.ts  → member invitations (send, list, revoke, accept)
//   members.ts  → memberships, roles, on-chain approver sync
//   schemas.ts  → shared zod request-body schemas
export async function authRoutes(app: FastifyInstance) {
  await app.register(authMeRoutes);
  await app.register(authOrgRoutes);
  await app.register(authInviteRoutes);
  await app.register(authMemberRoutes);
}
