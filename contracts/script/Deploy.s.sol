// SPDX-License-Identifier: MIT

pragma solidity ^0.8.24;

// NOTE: This deploy script requires Foundry to be installed to run.
//
// Run with:
// forge script script/Deploy.s.sol --rpc-url $ARC_RPC_URL --private-key $ADMIN_PRIVATE_KEY --broadcast

import "forge-std/Script.sol";

import "../src/AccessControlLite.sol";
import "../src/PolicyRegistry.sol";
import "../src/AuditLog.sol";
import "../src/SpendGuard.sol";

contract DeployScript is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("ADMIN_PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        vm.startBroadcast(deployerPrivateKey);

        // Deploy PolicyRegistry
        PolicyRegistry policyRegistry = new PolicyRegistry(deployer);

        // Deploy AuditLog
        AuditLog auditLog = new AuditLog(deployer);

        // Deploy SpendGuard with PolicyRegistry and AuditLog addresses
        SpendGuard spendGuard = new SpendGuard(
            deployer,
            address(policyRegistry),
            address(auditLog)
        );

        // Set up the contract relationships:
        // 1. Register SpendGuard as a guard on PolicyRegistry
        policyRegistry.setGuard(address(spendGuard), true);

        // 2. Register SpendGuard as a guard on AuditLog
        auditLog.setGuard(address(spendGuard), true);

        // 3. Set up an initial approver (using deployer for now)
        spendGuard.setApprover(deployer, true);

        vm.stopBroadcast();
    }
}
