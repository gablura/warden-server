// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// NOTE: This test file requires Foundry to be installed to run.
// Install Foundry first, then:
// 1. Uncomment line 8: import "forge-std/Test.sol";
// 2. Change line 11 to: contract PolicyRegistryTest is Test {

import {Test} from "forge-std/Test.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";

contract PolicyRegistryTest is Test {
    // TODO: After installing Foundry, change to: contract PolicyRegistryTest is Test {

    PolicyRegistry public registry;
    address public admin;
    address public guard;
    address public agent;
    address public counterparty;

    function setUp() public {
        admin = address(this);
        guard = address(0x1);
        agent = address(0x2);
        counterparty = address(0x3);

        registry = new PolicyRegistry(admin);
        registry.setGuard(guard, true);
    }

    function test_SetPolicy() public {
        uint256 dailyCap = 1000 * 10 ** 6;
        uint256 perTxCap = 100 * 10 ** 6;
        uint256 escalationThreshold = 50 * 10 ** 6;

        registry.setPolicy(agent, dailyCap, perTxCap, escalationThreshold);

        (
            uint256 dc,
            uint256 ptx,
            uint256 et,
            uint256 spent,
            uint256 lastReset,
            bool exists,
            ,
        ) = registry.policies(agent);

        assertEq(dc, dailyCap);
        assertEq(ptx, perTxCap);
        assertEq(et, escalationThreshold);
        assertEq(spent, 0);
        assertEq(lastReset, 0);
        assertTrue(exists);
    }

    function test_SetPolicy_RevertWhen_PerTxCapExceedsDailyCap() public {
        uint256 dailyCap = 100 * 10 ** 6;
        uint256 perTxCap = 200 * 10 ** 6;
        uint256 escalationThreshold = 50 * 10 ** 6;

        vm.expectRevert("perTxCap exceeds dailyCap");
        registry.setPolicy(agent, dailyCap, perTxCap, escalationThreshold);
    }

    function test_SetPolicy_RevertWhen_ThresholdExceedsPerTxCap() public {
        uint256 dailyCap = 1000 * 10 ** 6;
        uint256 perTxCap = 100 * 10 ** 6;
        uint256 escalationThreshold = 150 * 10 ** 6;

        vm.expectRevert("threshold exceeds perTxCap");
        registry.setPolicy(agent, dailyCap, perTxCap, escalationThreshold);
    }

    function test_SetAllowlist() public {
        registry.setAllowlist(agent, counterparty, true);
        assertTrue(registry.allowlist(agent, counterparty));
    }

    function test_CheckPolicy_NoPolicyForAgent() public {
        (bool allowed, bool needsApproval, string memory reason) = registry
            .checkPolicy(agent, counterparty, 100 * 10 ** 6);
        assertFalse(allowed);
        assertFalse(needsApproval);
        assertEq(reason, "no policy for agent");
    }

    function test_CheckPolicy_CounterpartyNotAllowlisted() public {
        uint256 dailyCap = 1000 * 10 ** 6;
        uint256 perTxCap = 100 * 10 ** 6;
        uint256 escalationThreshold = 50 * 10 ** 6;

        registry.setPolicy(agent, dailyCap, perTxCap, escalationThreshold);

        (bool allowed, bool needsApproval, string memory reason) = registry
            .checkPolicy(agent, counterparty, 100 * 10 ** 6);
        assertFalse(allowed);
        assertFalse(needsApproval);
        assertEq(reason, "counterparty not allowlisted");
    }

    function test_CheckPolicy_ExceedsPerTxCap() public {
        uint256 dailyCap = 1000 * 10 ** 6;
        uint256 perTxCap = 100 * 10 ** 6;
        uint256 escalationThreshold = 50 * 10 ** 6;

        registry.setPolicy(agent, dailyCap, perTxCap, escalationThreshold);
        registry.setAllowlist(agent, counterparty, true);

        (bool allowed, bool needsApproval, string memory reason) = registry
            .checkPolicy(agent, counterparty, 150 * 10 ** 6);
        assertFalse(allowed);
        assertFalse(needsApproval);
        assertEq(reason, "exceeds per-tx cap");
    }

    function test_CheckPolicy_ExceedsDailyCap() public {
        uint256 dailyCap = 100 * 10 ** 6;
        uint256 perTxCap = 100 * 10 ** 6;
        uint256 escalationThreshold = 50 * 10 ** 6;

        registry.setPolicy(agent, dailyCap, perTxCap, escalationThreshold);
        registry.setAllowlist(agent, counterparty, true);

        vm.prank(guard);
        registry.recordSpend(agent, 80 * 10 ** 6);

        (bool allowed, bool needsApproval, string memory reason) = registry
            .checkPolicy(agent, counterparty, 50 * 10 ** 6);
        assertFalse(allowed);
        assertFalse(needsApproval);
        assertEq(reason, "exceeds daily cap");
    }

    function test_CheckPolicy_NeedsApproval() public {
        uint256 dailyCap = 1000 * 10 ** 6;
        uint256 perTxCap = 100 * 10 ** 6;
        uint256 escalationThreshold = 50 * 10 ** 6;

        registry.setPolicy(agent, dailyCap, perTxCap, escalationThreshold);
        registry.setAllowlist(agent, counterparty, true);

        (bool allowed, bool needsApproval, string memory reason) = registry
            .checkPolicy(agent, counterparty, 75 * 10 ** 6);
        assertTrue(allowed);
        assertTrue(needsApproval);
        assertEq(reason, "");
    }

    function test_CheckPolicy_Allowed() public {
        uint256 dailyCap = 1000 * 10 ** 6;
        uint256 perTxCap = 100 * 10 ** 6;
        uint256 escalationThreshold = 50 * 10 ** 6;

        registry.setPolicy(agent, dailyCap, perTxCap, escalationThreshold);
        registry.setAllowlist(agent, counterparty, true);

        (bool allowed, bool needsApproval, string memory reason) = registry
            .checkPolicy(agent, counterparty, 25 * 10 ** 6);
        assertTrue(allowed);
        assertFalse(needsApproval);
        assertEq(reason, "");
    }

    function test_RecordSpend_FirstSpend() public {
        uint256 dailyCap = 1000 * 10 ** 6;
        uint256 perTxCap = 100 * 10 ** 6;
        uint256 escalationThreshold = 50 * 10 ** 6;

        registry.setPolicy(agent, dailyCap, perTxCap, escalationThreshold);

        vm.prank(guard);
        registry.recordSpend(agent, 100 * 10 ** 6);

        (, , , uint256 spent, uint256 lastReset, , , ) = registry.policies(agent);
        assertEq(spent, 100 * 10 ** 6);
        assertEq(lastReset, block.timestamp / 1 days);
    }

    function test_RecordSpend_RevertWhen_NoPolicyForAgent() public {
        vm.prank(guard);
        vm.expectRevert("no policy for agent");
        registry.recordSpend(agent, 100 * 10 ** 6);
    }

    function test_RecordSpend_RevertWhen_ExceedsDailyCap() public {
        uint256 dailyCap = 100 * 10 ** 6;
        uint256 perTxCap = 100 * 10 ** 6;
        uint256 escalationThreshold = 50 * 10 ** 6;

        registry.setPolicy(agent, dailyCap, perTxCap, escalationThreshold);

        vm.prank(guard);
        registry.recordSpend(agent, 100 * 10 ** 6);

        vm.prank(guard);
        vm.expectRevert("exceeds daily cap");
        registry.recordSpend(agent, 1 * 10 ** 6);
    }

    // Daily reset logic tests - these are critical as mentioned in the project brief
    function test_DailyReset_SameDay() public {
        uint256 dailyCap = 1000 * 10 ** 6;
        uint256 perTxCap = 100 * 10 ** 6;
        uint256 escalationThreshold = 50 * 10 ** 6;

        registry.setPolicy(agent, dailyCap, perTxCap, escalationThreshold);

        vm.prank(guard);
        registry.recordSpend(agent, 100 * 10 ** 6);

        vm.prank(guard);
        registry.recordSpend(agent, 50 * 10 ** 6);

        (, , , uint256 spent, uint256 lastReset, , , ) = registry.policies(agent);
        assertEq(spent, 150 * 10 ** 6);
        assertEq(lastReset, block.timestamp / 1 days);
    }

    function test_DailyReset_NewDay() public {
        uint256 dailyCap = 1000 * 10 ** 6;
        uint256 perTxCap = 100 * 10 ** 6;
        uint256 escalationThreshold = 50 * 10 ** 6;

        registry.setPolicy(agent, dailyCap, perTxCap, escalationThreshold);

        vm.prank(guard);
        registry.recordSpend(agent, 100 * 10 ** 6);

        vm.warp(block.timestamp + 1 days);

        vm.prank(guard);
        registry.recordSpend(agent, 200 * 10 ** 6);

        (, , , uint256 spent, uint256 lastReset, , , ) = registry.policies(agent);
        assertEq(spent, 200 * 10 ** 6);
        assertEq(lastReset, block.timestamp / 1 days);
    }

    function test_DailyReset_MultipleDays() public {
        uint256 dailyCap = 1000 * 10 ** 6;
        uint256 perTxCap = 100 * 10 ** 6;
        uint256 escalationThreshold = 50 * 10 ** 6;

        registry.setPolicy(agent, dailyCap, perTxCap, escalationThreshold);

        vm.prank(guard);
        registry.recordSpend(agent, 100 * 10 ** 6);

        vm.warp(block.timestamp + 1 days);
        vm.prank(guard);
        registry.recordSpend(agent, 200 * 10 ** 6);

        vm.warp(block.timestamp + 1 days);
        vm.prank(guard);
        registry.recordSpend(agent, 300 * 10 ** 6);

        (, , , uint256 spent, uint256 lastReset, , , ) = registry.policies(agent);
        assertEq(spent, 300 * 10 ** 6);
        assertEq(lastReset, block.timestamp / 1 days);
    }

    function test_DailyReset_CheckPolicyRespectsReset() public {
    uint256 dailyCap = 1000 * 10**6;
    uint256 perTxCap = 100 * 10**6;
    uint256 escalationThreshold = 50 * 10**6;

    registry.setPolicy(agent, dailyCap, perTxCap, escalationThreshold);
    registry.setAllowlist(agent, counterparty, true);

    vm.prank(guard);
    registry.recordSpend(agent, 950 * 10**6);

    (bool allowed1, , ) = registry.checkPolicy(
        agent,
        counterparty,
        100 * 10**6
    );
    assertFalse(allowed1);

    vm.warp(block.timestamp + 1 days);

    (bool allowed2, , ) = registry.checkPolicy(
        agent,
        counterparty,
        100 * 10**6
    );
    assertTrue(allowed2);
}
    function test_DailyReset_ExactlyDayBoundary() public {
        uint256 dailyCap = 1000 * 10 ** 6;
        uint256 perTxCap = 100 * 10 ** 6;
        uint256 escalationThreshold = 50 * 10 ** 6;

        registry.setPolicy(agent, dailyCap, perTxCap, escalationThreshold);

        uint256 startTime = (block.timestamp / 1 days) * 1 days;
        vm.warp(startTime);

        vm.prank(guard);
        registry.recordSpend(agent, 100 * 10 ** 6);

        vm.warp(startTime + 1 days);

        vm.prank(guard);
        registry.recordSpend(agent, 150 * 10 ** 6);

        (, , , uint256 spent, uint256 lastReset, , , ) = registry.policies(agent);
        assertEq(spent, 150 * 10 ** 6);
        assertEq(lastReset, (startTime + 1 days) / 1 days);
    }

    function test_AccessControl_OnlyAdminCanSetPolicy() public {
        uint256 dailyCap = 1000 * 10 ** 6;
        uint256 perTxCap = 100 * 10 ** 6;
        uint256 escalationThreshold = 50 * 10 ** 6;

        vm.prank(address(0x999));
        vm.expectRevert("not admin");
        registry.setPolicy(agent, dailyCap, perTxCap, escalationThreshold);
    }

    function test_AccessControl_OnlyAdminCanSetAllowlist() public {
        vm.prank(address(0x999));
        vm.expectRevert("not admin");
        registry.setAllowlist(agent, counterparty, true);
    }

    function test_AccessControl_OnlyGuardCanRecordSpend() public {
        uint256 dailyCap = 1000 * 10 ** 6;
        uint256 perTxCap = 100 * 10 ** 6;
        uint256 escalationThreshold = 50 * 10 ** 6;

        registry.setPolicy(agent, dailyCap, perTxCap, escalationThreshold);

        vm.prank(address(0x999));
        vm.expectRevert("not an authorized guard");
        registry.recordSpend(agent, 100 * 10 ** 6);
    }
}
