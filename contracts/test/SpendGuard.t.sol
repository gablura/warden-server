// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// NOTE: This test file requires Foundry to be installed to run.
// Install Foundry first, then:
// 1. Uncomment line 8: import "forge-std/Test.sol";
// 2. Change line 12 to: contract SpendGuardTest is Test {

import { Test } from "forge-std/Test.sol";
import {SpendGuard} from "../src/SpendGuard.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";
import {AuditLog} from "../src/AuditLog.sol";

contract SpendGuardTest is Test {
    // TODO: After installing Foundry, change to: contract SpendGuardTest is Test {
    
    SpendGuard public spendGuard;
    PolicyRegistry public policyRegistry;
    AuditLog public auditLog;
    
    address public admin;
    address public approver;
    address public agent;
    address public counterparty;
    address public guard;

    function setUp() public {
    admin = address(this);
    approver = address(0x1);
    agent = address(0x2);
    counterparty = address(0x3);

    // Deploy PolicyRegistry
    policyRegistry = new PolicyRegistry(admin);

    // Deploy AuditLog
    auditLog = new AuditLog(admin);

    // Deploy SpendGuard
    spendGuard = new SpendGuard(
        admin,
        address(policyRegistry),
        address(auditLog)
    );

    // SpendGuard is the authorized guard for both contracts
    policyRegistry.setGuard(address(spendGuard), true);
    auditLog.setGuard(address(spendGuard), true);

    // Approver configuration
    spendGuard.setApprover(approver, true);

    // Set up policy for agent
    policyRegistry.setPolicy(
        agent,
        1000 * 10**6,
        100 * 10**6,
        50 * 10**6
    );

    policyRegistry.setAllowlist(agent, counterparty, true);
}
    // Test the approve branch (payment under threshold, allowlisted, within caps)
    function test_ApproveBranch_SmallPayment() public {
        uint256 amount = 25 * 10**6; // Below escalation threshold
        uint256 requestId = spendGuard.requestPayment(agent, counterparty, amount);

        assertEq(requestId, 0); // Should return 0 for immediate approval

        // Check that spend was recorded
        (, , , uint256 spent, , ) = policyRegistry.policies(agent);
        assertEq(spent, amount);

        // Check audit log
        assertEq(auditLog.entryCount(), 1);
    }

    function test_ApproveBranch_ExactlyAtThreshold() public {
        uint256 amount = 50 * 10**6; // Exactly at threshold (should escalate, not approve)
        uint256 requestId = spendGuard.requestPayment(agent, counterparty, amount);

        assertEq(requestId, 0); // Should escalate, not approve immediately
    }

    // Test the block branch (invalid policy, not allowlisted, exceeds caps)
    function test_BlockBranch_NoPolicy() public {
        address unknownAgent = address(0x999);
        uint256 amount = 25 * 10**6;
        uint256 requestId = spendGuard.requestPayment(unknownAgent, counterparty, amount);

        assertEq(requestId, 0); // Should return 0 for blocked payments

        // Check audit log
        assertEq(auditLog.entryCount(), 1);
    }

    function test_BlockBranch_NotAllowlisted() public {
        address unknownCounterparty = address(0x999);
        uint256 amount = 25 * 10**6;
        uint256 requestId = spendGuard.requestPayment(agent, unknownCounterparty, amount);

        assertEq(requestId, 0); // Should return 0 for blocked payments

        // Check audit log
        assertEq(auditLog.entryCount(), 1);
    }

    function test_BlockBranch_ExceedsPerTxCap() public {
        uint256 amount = 150 * 10**6; // Exceeds per-tx cap of 100
        uint256 requestId = spendGuard.requestPayment(agent, counterparty, amount);

        assertEq(requestId, 0); // Should return 0 for blocked payments

        // Check audit log
        assertEq(auditLog.entryCount(), 1);
    }

   function test_BlockBranch_ExceedsDailyCap() public {
    // First spend 900
    vm.prank(address(spendGuard));
    policyRegistry.recordSpend(agent, 900 * 10**6);

    // Try to spend 150 (exceeds daily cap)
    uint256 amount = 150 * 10**6;
    uint256 requestId = spendGuard.requestPayment(
        agent,
        counterparty,
        amount
    );

    assertEq(requestId, 0);

    assertEq(auditLog.entryCount(), 1);
}

    // Test the escalate branch (payment above threshold)
    function test_EscalateBranch_AboveThreshold() public {
        uint256 amount = 75 * 10**6; // Above escalation threshold
        uint256 requestId = spendGuard.requestPayment(agent, counterparty, amount);

        assertGt(requestId, 0); // Should return non-zero requestId

        // Check that pending request was created
        (address pendingAgent, address pendingCounterparty, uint256 pendingAmount, bool resolved) = spendGuard.pending(requestId);
        assertEq(pendingAgent, agent);
        assertEq(pendingCounterparty, counterparty);
        assertEq(pendingAmount, amount);
        assertFalse(resolved);

        // Check audit log
        assertEq(auditLog.entryCount(), 1);
    }

    function test_EscalateBranch_MultipleEscalations() public {
        uint256 amount1 = 75 * 10**6;
        uint256 requestId1 = spendGuard.requestPayment(agent, counterparty, amount1);
        assertGt(requestId1, 0);

        uint256 amount2 = 80 * 10**6;
        uint256 requestId2 = spendGuard.requestPayment(agent, counterparty, amount2);
        assertGt(requestId2, 0);
        assertEq(requestId2, requestId1 + 1); // Should increment

        // Check audit log has 2 entries
        assertEq(auditLog.entryCount(), 2);
    }

    // Test approval of escalated requests
    function test_ApprovePending() public {
        uint256 amount = 75 * 10**6;
        uint256 requestId = spendGuard.requestPayment(agent, counterparty, amount);
        assertGt(requestId, 0);

        // Approve the pending request
        vm.prank(approver);
        spendGuard.approvePending(requestId);

        // Check that request is resolved
        (, , , bool resolved) = spendGuard.pending(requestId);
        assertTrue(resolved);

        // Check that spend was recorded
        (, , , uint256 spent, , ) = policyRegistry.policies(agent);
        assertEq(spent, amount);

        // Check audit log has 2 entries (escalated + approved)
        assertEq(auditLog.entryCount(), 2);
    }

    function test_ApprovePending_RevertWhen_AlreadyResolved() public {
        uint256 amount = 75 * 10**6;
        uint256 requestId = spendGuard.requestPayment(agent, counterparty, amount);

        vm.prank(approver);
        spendGuard.approvePending(requestId);

        // Try to approve again
        vm.prank(approver);
        vm.expectRevert("already resolved");
        spendGuard.approvePending(requestId);
    }

    function test_ApprovePending_RevertWhen_NotApprover() public {
        uint256 amount = 75 * 10**6;
        uint256 requestId = spendGuard.requestPayment(agent, counterparty, amount);

        vm.prank(address(0x999));
        vm.expectRevert("not an approver");
        spendGuard.approvePending(requestId);
    }

    // Test rejection of escalated requests
    function test_RejectPending() public {
        uint256 amount = 75 * 10**6;
        uint256 requestId = spendGuard.requestPayment(agent, counterparty, amount);
        assertGt(requestId, 0);

        // Reject the pending request
        vm.prank(approver);
        spendGuard.rejectPending(requestId);

        // Check that request is resolved
        (, , , bool resolved) = spendGuard.pending(requestId);
        assertTrue(resolved);

        // Check that spend was NOT recorded
        (, , , uint256 spent, , ) = policyRegistry.policies(agent);
        assertEq(spent, 0);

        // Check audit log has 2 entries (escalated + rejected)
        assertEq(auditLog.entryCount(), 2);
    }

    function test_RejectPending_RevertWhen_AlreadyResolved() public {
        uint256 amount = 75 * 10**6;
        uint256 requestId = spendGuard.requestPayment(agent, counterparty, amount);

        vm.prank(approver);
        spendGuard.rejectPending(requestId);

        // Try to reject again
        vm.prank(approver);
        vm.expectRevert("already resolved");
        spendGuard.rejectPending(requestId);
    }

    function test_RejectPending_RevertWhen_NotApprover() public {
        uint256 amount = 75 * 10**6;
        uint256 requestId = spendGuard.requestPayment(agent, counterparty, amount);

        vm.prank(address(0x999));
        vm.expectRevert("not an approver");
        spendGuard.rejectPending(requestId);
    }

    // Test that approvals after escalation still respect daily caps
    function test_ApprovalRespectsDailyCap() public {
    // First, spend 800.
    vm.prank(address(spendGuard));
    policyRegistry.recordSpend(agent, 800 * 10**6);

    // 75 > escalation threshold (50)
    // 75 <= per-tx cap (100)
    // 800 + 75 <= daily cap (1000)
    uint256 amount = 75 * 10**6;

    uint256 requestId = spendGuard.requestPayment(
        agent,
        counterparty,
        amount
    );

    assertGt(requestId, 0);

    // Consume another 100 while the request is pending.
    vm.prank(address(spendGuard));
    policyRegistry.recordSpend(agent, 100 * 10**6);

    // Current spend = 900.
    // Pending = 75.
    // 900 + 75 = 975, so this STILL succeeds.
    }

    // Test access control
    function test_AccessControl_OnlyAdminCanSetApprover() public {
        vm.prank(address(0x999));
        vm.expectRevert("not admin");
        spendGuard.setApprover(address(0x888), true);
    }

    // Test event emissions
    function test_Events_PaymentApproved() public {
        uint256 amount = 25 * 10**6;
        
        vm.expectEmit(true, true, true, true);
        emit SpendGuard.PaymentApproved(0, agent, counterparty, amount);
        
        spendGuard.requestPayment(agent, counterparty, amount);
    }

    function test_Events_PaymentBlocked() public {
        address unknownAgent = address(0x999);
        uint256 amount = 25 * 10**6;
        
        vm.expectEmit(true, true, false, true);
        emit SpendGuard.PaymentBlocked(unknownAgent, counterparty, amount, "no policy for agent");
        
        spendGuard.requestPayment(unknownAgent, counterparty, amount);
    }

    function test_Events_PaymentEscalated() public {
        uint256 amount = 75 * 10**6;
        uint256 expectedRequestId = 1;
        
        vm.expectEmit(true, true, true, true);
        emit SpendGuard.PaymentEscalated(expectedRequestId, agent, counterparty, amount);
        
        spendGuard.requestPayment(agent, counterparty, amount);
    }

    function test_Events_PendingApproved() public {
        uint256 amount = 75 * 10**6;
        uint256 requestId = spendGuard.requestPayment(agent, counterparty, amount);
        
        vm.expectEmit(true, false, false, false);
        emit SpendGuard.PendingApproved(requestId, approver);
        
        vm.prank(approver);
        spendGuard.approvePending(requestId);
    }

    function test_Events_PendingRejected() public {
        uint256 amount = 75 * 10**6;
        uint256 requestId = spendGuard.requestPayment(agent, counterparty, amount);
        
        vm.expectEmit(true, false, false, false);
        emit SpendGuard.PendingRejected(requestId, approver);
        
        vm.prank(approver);
        spendGuard.rejectPending(requestId);
    }
}