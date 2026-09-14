// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// NOTE: This test file requires Foundry to be installed to run.
// Install Foundry first, then:
// 1. Uncomment line 8: import "forge-std/Test.sol";
// 2. Change line 11 to: contract AuditLogTest is Test {

import { Test } from "forge-std/Test.sol";
import {AuditLog} from "../src/AuditLog.sol";

contract AuditLogTest is Test {
    // TODO: After installing Foundry, change to: contract AuditLogTest is Test {
    
    AuditLog public auditLog;
    address public admin;
    address public guard;
    address public agent;
    address public counterparty;

    function setUp() public {
        admin = address(this);
        guard = address(0x1);
        agent = address(0x2);
        counterparty = address(0x3);

        auditLog = new AuditLog(admin);
        auditLog.setGuard(guard, true);
    }

    function test_Record() public {
        uint256 amount = 100 * 10**6;
        string memory decision = "approved";

        vm.prank(guard);
        auditLog.record(agent, counterparty, amount, decision);

        assertEq(auditLog.entryCount(), 1);

        (address loggedAgent, address loggedCounterparty, uint256 loggedAmount, string memory loggedDecision, uint256 timestamp) = auditLog.entries(0);
        
        assertEq(loggedAgent, agent);
        assertEq(loggedCounterparty, counterparty);
        assertEq(loggedAmount, amount);
        assertEq(loggedDecision, decision);
        assertGt(timestamp, 0);
    }

    function test_Record_MultipleEntries() public {
        vm.prank(guard);
        auditLog.record(agent, counterparty, 100 * 10**6, "approved");
        
        vm.prank(guard);
        auditLog.record(agent, counterparty, 50 * 10**6, "blocked: exceeds cap");

        assertEq(auditLog.entryCount(), 2);
    }

    function test_Record_RevertWhen_NotGuard() public {
        vm.prank(address(0x999));
        vm.expectRevert("not an authorized guard");
        auditLog.record(agent, counterparty, 100 * 10**6, "approved");
    }

    function test_EntryCount() public {
        assertEq(auditLog.entryCount(), 0);

        vm.prank(guard);
        auditLog.record(agent, counterparty, 100 * 10**6, "approved");
        
        assertEq(auditLog.entryCount(), 1);

        vm.prank(guard);
        auditLog.record(agent, counterparty, 50 * 10**6, "escalated");
        
        assertEq(auditLog.entryCount(), 2);
    }

    function test_RecordedEvent() public {
        uint256 amount = 100 * 10**6;
        string memory decision = "approved";

        vm.expectEmit(true, true, true, false);
        emit AuditLog.Recorded(0, agent, counterparty, amount, decision, block.timestamp);

        vm.prank(guard);
        auditLog.record(agent, counterparty, amount, decision);
    }

    function test_DifferentDecisionTypes() public {
        string[] memory decisions = new string[](5);
        decisions[0] = "approved";
        decisions[1] = "blocked: no policy";
        decisions[2] = "escalated";
        decisions[3] = "approved-after-escalation";
        decisions[4] = "rejected-after-escalation";

        for (uint256 i = 0; i < decisions.length; i++) {
            vm.prank(guard);
            auditLog.record(agent, counterparty, 100 * 10**6, decisions[i]);
        }

        assertEq(auditLog.entryCount(), 5);

        // Verify each entry
        for (uint256 i = 0; i < decisions.length; i++) {
            (, , , string memory loggedDecision, ) = auditLog.entries(i);
            assertEq(loggedDecision, decisions[i]);
        }
    }
function test_TimestampAccuracy() public {
    uint256 beforeTimestamp = block.timestamp;

    vm.warp(beforeTimestamp + 1);

    vm.prank(guard);
    auditLog.record(agent, counterparty, 100 * 10**6, "approved");

    (, , , , uint256 loggedTimestamp) = auditLog.entries(0);

    assertEq(loggedTimestamp, block.timestamp);
    assertGt(loggedTimestamp, beforeTimestamp);
}

    function test_LargeAmounts() public {
        uint256 largeAmount = 1_000_000 * 10**6; // 1 million USDC

        vm.prank(guard);
        auditLog.record(agent, counterparty, largeAmount, "approved");

        (, , uint256 loggedAmount, , ) = auditLog.entries(0);
        assertEq(loggedAmount, largeAmount);
    }

    function test_ZeroAmount() public {
        vm.prank(guard);
        auditLog.record(agent, counterparty, 0, "approved");

        (, , uint256 loggedAmount, , ) = auditLog.entries(0);
        assertEq(loggedAmount, 0);
    }

    function test_SetGuard() public {
        address newGuard = address(0x5);
        auditLog.setGuard(newGuard, true);
        assertTrue(auditLog.guards(newGuard));
    }

    function test_SetGuard_RevertWhen_NotAdmin() public {
        vm.prank(address(0x999));
        vm.expectRevert("not admin");
        auditLog.setGuard(address(0x5), true);
    }
}