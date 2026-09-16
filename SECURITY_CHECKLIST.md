# Security Checklist - Warden Project

## ✅ Protected Files (Gitignored)

### Environment Variables (CRITICAL SECURITY)
- ✅ `.env` - Contains private keys and RPC URLs
- ✅ `.env.local` - Local environment overrides
- ✅ `.env.*.local` - Local environment variants
- ✅ contracts/.env - Contract deployment keys
- ✅ contracts/.env.local - Contract local overrides

### Foundry Deployment Artifacts (SENSITIVE DATA)
- ✅ `contracts/broadcast/` - Deployment transaction data
- ✅ `contracts/cache/` - Deployment sensitive data
- ✅ `contracts/broadcast/**/run-latest.json` - Contains deployment keys
- ✅ `contracts/cache/**/run-latest.json` - Contains deployment keys
- ✅ `contracts/out/` - Compiled bytecode
- ✅ `contracts/lib/` - External dependencies

### Standard Project Files
- ✅ `node_modules/` - Dependencies
- ✅ `dist/`, `build/` - Build outputs
- ✅ `*.log` - Log files
- ✅ `.vscode/`, `.idea/` - IDE settings
- ✅ `.DS_Store`, `Thumbs.db` - OS files

## ✅ Allowed Files (Safe to Commit)
- ✅ `.env.example` - Template for environment variables (no actual keys)
- ✅ `contracts/.env.example` - Contract deployment template
- ✅ Source code files
- ✅ Configuration files
- ✅ Documentation

## 🔒 Security Practices Implemented

### 1. Private Key Protection
- ✅ Private keys stored in `.env` files only
- ✅ `.env` files gitignored at multiple levels
- ✅ No private keys in source code
- ✅ No private keys in configuration files

### 2. Deployment Data Protection
- ✅ Foundry deployment sensitive data gitignored
- ✅ Broadcast files with deployment keys protected
- ✅ Cache files with sensitive data protected

### 3. Separation of Concerns
- ✅ Root `.gitignore` for warden-server
- ✅ contracts/.gitignore for smart contracts
- ✅ Overlapping protection for shared directories

## 🎯 Security Verification

### Test Command Results
```bash
# .env files are properly ignored
git check-ignore -v .env          # ✅ Ignored
git check-ignore -v .env.example  # ✅ Allowed

# Sensitive deployment data is protected
git check-ignore -v broadcast/**/run-latest.json  # ✅ Ignored
git check-ignore -v cache/**/run-latest.json       # ✅ Ignored
```

## 📋 Current Status

### Protected Sensitive Files Present
- `warden-server/.env` (contains ADMIN_PRIVATE_KEY, APPROVER_PRIVATE_KEY)
- `contracts/.env` (contains deployment keys, contract addresses)
- `contracts/broadcast/Deploy.s.sol/5042002/run-latest.json` (deployment data)
- `contracts/cache/Deploy.s.sol/5042002/run-latest.json` (deployment data)

### Safe Files Ready for Commit
- Source code
- Configuration files
- `.env.example` templates
- Documentation

## ⚠️ Security Reminders

1. **Never commit `.env` files** - They contain actual private keys
2. **Never share private keys** - Even with team members
3. **Use different keys for testnet/mainnet** - Separate environments
4. **Rotate keys if compromised** - Immediately update `.env` files
5. **Use hardware wallets for production** - Enhanced security
6. **Review git status before committing** - Ensure no sensitive files included

## 🔐 Recommended Next Steps

1. **Initialize git repository** (if not already done)
2. **Review git status** to ensure only safe files are staged
3. **Create initial commit** with safe files only
4. **Set up branch protection** (for production)
5. **Consider using secrets management** for production deployments

## 🔍 Contract-Level Static Analysis (Hardening Review §5.4) — ✅ RUN 2026-09-16

Slither (0.10.x, solc 0.8.37) was run against all four contracts. Results:

| Contract | Findings | Disposition |
|---|---|---|
| AuditLog | 0 | clean |
| AccessControlLite | 0 | clean |
| SpendGuard | 2 → 0 | `arbitrary-send-erc20` on `_settle` (that IS the non-custodial pull model — `from` is the policy-checked agent who granted the allowance) and `reentrancy-benign` (neutralized by `nonReentrant` + trusted immutable registry). Both suppressed in-source with the reasoning inline. |
| PolicyRegistry | 12 → 0 | one class: the per-UTC-day cap accounting (`block.timestamp / 1 days` equalities/comparisons). Both comparison sides derive from the same block's timestamp and a missed day-boundary is conservative (spend carries over capped, never unbounded). Scoped region suppression with the full argument in-source. |

Re-running (do this after ANY contract change, and again right before mainnet):

```bash
pip install slither-analyzer
# The repo's foundry.toml forces Slither's Foundry platform; when forge is
# unavailable (e.g. forge missing from PATH), the src/ contracts compile
# standalone — they only use same-directory imports:
cp contracts/src/*.sol tmp/slither-run/ && cd tmp/slither-run && slither SpendGuard.sol && slither PolicyRegistry.sol && slither AuditLog.sol && slither AccessControlLite.sol
# With forge installed, the direct form works:
cd contracts && slither src/SpendGuard.sol
```

⚠️ **Forge was not installed on this machine at triage time** (`.foundry/bin` empty) — reinstall (`foundryup` or foundry installation script) and re-run `forge test` (expect 97 passing) before mainnet. A clean Slither run is a prerequisite for any mainnet deployment.

## 🚨 Incident Response Plan (Hardening Review §5.5)

### Scenario 1: "We think a key leaked"

1. **Rotate immediately.** Generate new API keys (or new private keys for admin/approver wallets). Update `.env` and redeploy — the server only reads keys at boot. Note: an API key configured as a credential's `previousKey` stays accepted during the rotation grace window (see `WARDEN_API_KEYS` in `.env.example`) — drop the `previousKey` segment once clients have migrated, or immediately if the key is known-compromised.
2. **Pause the contracts.** Call `setPaused(true)` on SpendGuard (admin-only, freezes settlement immediately). PolicyRegistry has no pause — the global daily ceiling (`setGlobalDailyCap`) is its circuit breaker.
3. **Audit the trail.** Query `operator_actions` by `correlation_id` and timestamp to find what the compromised key did. Cross-reference with on-chain events via the tx hashes.
4. **Rotate the wallet.** If an admin or approver *private key* leaked (not just an API key), generate a new key pair, deploy new contract instances (or transfer ownership), and update all server config.
5. **Notify.** Alert anyone who transacted during the exposure window.

### Scenario 2: "We think a policy was set incorrectly"

1. **Fix the policy.** Submit a corrective `setPolicy` transaction with the correct caps. Decreases apply immediately; a correction that *raises* `dailyCap` goes through the 1-day timelock (`applyPolicy`) — if that delay is unacceptable during an incident, `cancelPolicyChange` is available, and tightening other knobs (perTxCap, escalationThreshold) can be done in the same call that applies immediately only when dailyCap does not increase.
2. **Check for over-spending.** Query `/audit` and `operator_actions` for the window between the incorrect policy and the fix. If spending exceeded intent, document it.
3. **Verify on-chain.** Read the policy from PolicyRegistry directly to confirm the correction landed.
4. **Review the input path.** How did the wrong value get submitted? API typo? Bug in the dashboard? Add validation (e.g., a confirmation step for cap changes above a threshold) to prevent recurrence.

### Scenario 3: "The indexer is lagging / stuck"

1. **Check `/status`** for current lag. Under 100 blocks is normal; over 1000 means the watcher has stalled.
2. **Check server logs** for `[payments:*]` or `[policies:*]` error lines — the runner logs every failed event with its tx hash.
3. **Restart the server** if the watcher is stuck. The indexer resumes from its last checkpoint on boot — no events are lost.
4. **If the RPC is the bottleneck** (rate limiting, timeouts): backup RPC endpoints set via `ARC_RPC_FALLBACK_URLS` (comma-separated, see `.env.example`) fail over automatically — viem's fallback transport demotes a failing primary and re-issues requests against the backups, for reads and transaction submission alike. If no fallbacks are configured, add one and redeploy; the manual swap of `ARC_RPC_URL` still works as a last resort.

### Scenario 4: "We need to emergency-stop all settlement"

1. **Pause the SpendGuard contract** via the admin function (`setPaused`). This freezes all money movement: new payments and approvals revert. Rejections stay available while paused by design, so approvers can empty the queue during the incident.
2. **Stop the server.** This prevents any further API requests from reaching the contracts.
3. **Investigate.** Use the audit log and on-chain events to understand what happened.
4. **Do not unpause** until the root cause is identified and fixed.

## 🚨 What to Do If .env Files Were Committed

If sensitive files were accidentally committed:
1. **Immediately remove from git**: `git rm --cached .env`
2. **Add to .gitignore**: Ensure proper gitignore rules
3. **Force push changes**: Remove from remote repository
4. **Rotate all exposed keys**: Generate new private keys
5. **Update all references**: Update deployed contracts if needed

---

## 🚀 Mainnet Go-Live Checklist (hardening review — remaining items)

Every box checked is a precondition for pointing Warden at real money:

- [ ] **`forge test` re-run green (97 tests)** — forge must be reinstalled first (see §5.4 note above).
- [ ] **Slither re-run with 0 findings** after the last contract edit.
- [ ] **`globalDailyCap` set to a concrete value** — it deploys as `type(uint256).max` (unlimited) by design; an unset ceiling means the circuit breaker doesn't exist. `setGlobalDailyCap(...)` post-deploy, before any traffic.
- [ ] **Request-signing window closed** — `UNSIGNED_REQUESTS_ALLOWED_UNTIL=2026-10-01T00:00:00Z` is set in `.env`; verify boot logs show "Request signing enforced" (or flip `REQUIRE_SIGNED_REQUESTS=true` directly) once service callers have adopted `scripts/signed-request-example.mjs`.
- [ ] **Per-org deployments configured** — `WARDEN_NETWORK=mainnet` plus each org's five fields (`mainnetPolicyRegistry`, `mainnetSpendGuard`, `mainnetAuditLog`, `mainnetRpcUrl`, `mainnetChainId`). Partial configs fail loudly at resolution (OrgDeploymentError) — that is the intended behavior.
- [ ] **Agent org backfill run once** — `npx tsx scripts/backfill-agent-orgs.ts` immediately after enabling per-org deployments (stamps agents indexed before the tenant-scoping change; idempotent, safe against a live server).
- [ ] **Backup RPC configured** — `ARC_RPC_FALLBACK_URLS` with at least one independent endpoint (failover is automatic; see incident scenario 3).
- [ ] **Production origins allowlisted** — `CORS_ORIGIN` includes the production dashboard origin (it feeds both CORS and the `/ws` upgrade origin check).
- [ ] **Keyset/limits verified under load** — `/audit`, `/agents`, `/approvals` cap at `MAX_LIMIT=200`; no unbounded reads remain.

## 🧯 Ops Drill Checklist (incident plan §5.5 — rehearse, don't just read)

The plan above is only as good as the last time someone walked it. Each drill on **testnet**, dated when done:

- [ ] **Key-rotation drill** — rotate one `WARDEN_API_KEYS` credential via the `previousKey` grace window; verify both keys work, then drop `previousKey` and verify only the new key works.
- [ ] **Pause drill** — `setPaused(true)` on the testnet SpendGuard; verify `requestPayment` reverts `ContractPaused`, `rejectPending` still succeeds, then unpause.
- [ ] **RPC failover drill** — set `ARC_RPC_URL` to a dead endpoint with `ARC_RPC_FALLBACK_URLS` populated; verify reads, tx submission, and the indexer keep working through the fallback.
- [ ] **Indexer recovery drill** — kill the server mid-stream, restart; verify the boot backfill resumes from the checkpoint with zero double-counted spend (`ProcessedLog` idempotency) and zero gaps.
- [ ] **Incident tabletop** — walk Scenario 1 (key leak) end to end on testnet using only the written plan; fix the plan where the walkthrough stalls.

---

**Status**: ✅ All sensitive files properly protected · Slither triage complete 2026-09-16
**Date**: 2026-09-16
**Last Verified**: Git ignore rules confirmed functional; contract static analysis clean (see §5.4)