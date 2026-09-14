# Warden Smart Contracts

Smart contracts for the Warden governance and visibility layer for AI agent spending.

## Project Structure

```
contracts/
├── src/                    # Solidity contract source files
│   ├── AccessControlLite.sol
│   ├── PolicyRegistry.sol
│   ├── SpendGuard.sol
│   └── AuditLog.sol
├── script/                 # Deployment scripts
│   └── Deploy.s.sol
├── test/                   # Foundry test files
│   ├── AccessControlLite.t.sol
│   ├── PolicyRegistry.t.sol
│   ├── SpendGuard.t.sol
│   └── AuditLog.t.sol
├── lib/                    # External dependencies
├── foundry.toml           # Foundry configuration
├── package.json          # NPM scripts for convenience
└── .env.example          # Environment variables template
```

## Prerequisites

You need to install Foundry (forge, cast, anvil) to build and test these contracts.

### Installing Foundry

```bash
# On Linux/Mac
curl -L https://foundry.paradigm.xyz | bash
foundryup

# On Windows
# Download and install from https://github.com/foundry-rs/foundry/releases
# Or use WSL2 and follow the Linux instructions
```

### Completing Test Files After Foundry Installation

The test files are written but require Foundry to be installed to run. After installing Foundry:

1. **Uncomment Foundry imports** in each test file:
   - `test/AccessControlLite.t.sol`: Uncomment line 8, change line 11 to `contract AccessControlLiteTest is Test {`
   - `test/PolicyRegistry.t.sol`: Uncomment line 8, change line 11 to `contract PolicyRegistryTest is Test {`
   - `test/SpendGuard.t.sol`: Uncomment line 8, change line 12 to `contract SpendGuardTest is Test {`
   - `test/AuditLog.t.sol`: Uncomment line 8, change line 11 to `contract AuditLogTest is Test {`

2. **Uncomment deploy script import**:
   - `script/Deploy.s.sol`: Uncomment line 7, change line 13 to `contract DeployScript is Script {`

## Building

```bash
npm run build
# or
forge build
```

## Testing

```bash
npm run test
# or
forge test

# With gas reporting
npm run test:gas
# or
forge test --gas-report

# Run specific test file
forge test --match test test/PolicyRegistry.t.sol
```

### Test Coverage

The test suite includes:

- **PolicyRegistry tests**: Policy setting, allowlist management, policy checking, spend recording, and **critical daily reset logic**
- **SpendGuard tests**: All three branches (approve, block, escalate), pending request handling, and access control
- **AuditLog tests**: Entry recording, event emission, and access control
- **AccessControlLite tests**: Role management and access control

## Deployment

The contracts are designed to be deployed to Arc (Circle's EVM-compatible L1).

### Environment Variables

Set up the following environment variables:

```bash
# Copy the example environment file
cp .env.example .env

# Edit .env with your values
ARC_RPC_URL=https://arc-testnet.circle.com
ARC_CHAIN_ID=1234567890 # Replace with actual Arc chain ID
ADMIN_PRIVATE_KEY=0x... # Your admin wallet private key
APPROVER_PRIVATE_KEY=0x... # Your approver wallet private key
```

### Deploy to Testnet

```bash
npm run deploy:testnet
# or
forge script script/Deploy.s.sol --rpc-url $ARC_TESTNET_RPC_URL --private-key $ADMIN_PRIVATE_KEY --broadcast --verify
```

### Deploy to Mainnet

```bash
npm run deploy
# or
forge script script/Deploy.s.sol --rpc-url $ARC_RPC_URL --private-key $ADMIN_PRIVATE_KEY --broadcast
```

## Contract Overview

### AccessControlLite
Minimal role management with admin, approver, and guard roles. Used as base contract for all other contracts.

### PolicyRegistry
Source of truth for agent spending policies (daily caps, per-tx caps, escalation thresholds, allowlists). Contains critical daily reset logic for spend tracking.

### SpendGuard
The gate every agent payment passes through. Checks policies, handles escalation, and records decisions. Has three main branches: approve, block, and escalate.

### AuditLog
Immutable record of every spend decision for compliance exports. Stores all approval, block, and escalation events.

## Development Notes

- Uses Solidity ^0.8.24
- Optimized with 200 runs
- Designed for Arc chain (USDC as native gas)
- No external dependencies - uses minimal custom AccessControl instead of OpenZeppelin
- All tests include proper setup and teardown
- Daily reset logic extensively tested (same day, new day, multiple days, day boundaries)

## Next Steps After Foundry Installation

1. Install Foundry and complete the test file modifications mentioned above
2. Run `forge build` to verify contracts compile
3. Run `forge test` to verify all tests pass
4. Set up environment variables for Arc network
5. Deploy to Arc testnet using the deploy script
6. Verify deployment and contract interactions
7. Update the backend server with deployed contract addresses