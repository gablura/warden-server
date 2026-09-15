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

## 🔍 Contract-Level Static Analysis (Hardening Review §5.4)

Before mainnet deployment, run Slither on all four contracts (PolicyRegistry, SpendGuard, AuditLog, WardenFactory). Slither catches classes of bugs that hand-written Foundry tests often don't cover: reentrancy patterns, unchecked external calls, integer overflow in Solidity <0.8, and storage layout issues.

```bash
# Install Slither (requires Python + pip)
pip install slither-analyzer

# Run on each contract
cd contracts
slither src/PolicyRegistry.sol --foundry-compile-all
slither src/SpendGuard.sol --foundry-compile-all
slither src/AuditLog.sol --foundry-compile-all
slither src/WardenFactory.sol --foundry-compile-all
```

Review every finding. False positives are common — suppress them with `// slither-disable-next-line` comments in the contract with a note explaining why the finding doesn't apply. A clean Slither run is a prerequisite for any mainnet deployment.

## 🚨 Incident Response Plan (Hardening Review §5.5)

### Scenario 1: "We think a key leaked"

1. **Rotate immediately.** Generate new API keys (or new private keys for admin/approver wallets). Update `.env` and redeploy — the server only reads keys at boot, so a restart invalidates the old ones.
2. **Pause the contracts.** Call `pause()` on SpendGuard and PolicyRegistry (if pause is available). If no pause function exists, coordinate an emergency upgrade or rely on the global ceiling as a circuit breaker.
3. **Audit the trail.** Query `operator_actions` by `correlation_id` and timestamp to find what the compromised key did. Cross-reference with on-chain events via the tx hashes.
4. **Rotate the wallet.** If an admin or approver *private key* leaked (not just an API key), generate a new key pair, deploy new contract instances (or transfer ownership), and update all server config.
5. **Notify.** Alert anyone who transacted during the exposure window.

### Scenario 2: "We think a policy was set incorrectly"

1. **Fix the policy.** Submit a corrective `setPolicy` transaction with the correct caps. The policy update takes effect immediately on-chain.
2. **Check for over-spending.** Query `/audit` and `operator_actions` for the window between the incorrect policy and the fix. If spending exceeded intent, document it.
3. **Verify on-chain.** Read the policy from PolicyRegistry directly to confirm the correction landed.
4. **Review the input path.** How did the wrong value get submitted? API typo? Bug in the dashboard? Add validation (e.g., a confirmation step for cap changes above a threshold) to prevent recurrence.

### Scenario 3: "The indexer is lagging / stuck"

1. **Check `/status`** for current lag. Under 100 blocks is normal; over 1000 means the watcher has stalled.
2. **Check server logs** for `[payments:*]` or `[policies:*]` error lines — the runner logs every failed event with its tx hash.
3. **Restart the server** if the watcher is stuck. The indexer resumes from its last checkpoint on boot — no events are lost.
4. **If the RPC is the bottleneck** (rate limiting, timeouts), switch to a backup RPC endpoint by updating `ARC_RPC_URL` and redeploying.

### Scenario 4: "We need to emergency-stop all settlement"

1. **Pause the SpendGuard contract** via the admin function. This blocks all new payments, approvals, and rejections.
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

**Status**: ✅ All sensitive files properly protected
**Date**: 2026-09-14
**Last Verified**: Git ignore rules confirmed functional