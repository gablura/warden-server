-- Reconcile the users table with the Prisma schema: identity moved from a
-- Google-direct subject (`googleId`) to Clerk (`clerkId`), but no migration
-- ever renamed the column — so every Clerk-authenticated request failed with
-- P2022 "column users.clerkId does not exist".
--
-- The rename preserves the existing value and its uniqueness: the old Google
-- subject becomes the row's clerkId verbatim. It will never collide with a
-- real Clerk `user_...` id, so at worst a pre-Clerk row is treated as a
-- distinct identity going forward — no rows, memberships, or wallets are
-- lost or re-linked by this migration.
--
-- Legacy `role` / `isProductionAccess` columns are intentionally left in
-- place: the app no longer reads them (roles live on Memberships), and
-- dropping user data is riskier than ignoring it.
ALTER TABLE "users" RENAME COLUMN "googleId" TO "clerkId";
ALTER INDEX "users_googleId_key" RENAME TO "users_clerkId_key";
-- The schema declares clerkId as optional (users can exist ahead of their
-- first Clerk linkage), so drop the inherited NOT NULL from the old column.
ALTER TABLE "users" ALTER COLUMN "clerkId" DROP NOT NULL;
