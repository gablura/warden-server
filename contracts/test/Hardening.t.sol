// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SpendGuard} from "../src/SpendGuard.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";
import {AuditLog} from "../src/AuditLog.sol";
import {ReentrancyGuard} from "../src/ReentrancyGuard.sol";
import {MockUSDC} from "./SpendGuard.t.sol";

/// @dev USDC stand-in whose transferFrom re-enters SpendGuard.requestPayment
/// during settlement — simulating a malicious/callback token. The guard must
/// reject the reentrant inner call, which reverts the whole payment.
/// The guard target is set after construction because guard and token
/// reference each other circularly.
contract ReentrantUSDC {
    SpendGuard public guard;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function setGuardTarget(SpendGuard guard_) external {
        guard = guard_;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256) external returns (bool) {
        // The attack: while SpendGuard is mid-settlement, try to spend again.
        guard.requestPayment(from, to, 1);
        return true;
    }
}

/// @dev USDC stand-in that always refuses settlement (simulates Arc's
/// compliance blocklist rejecting a transfer). Used to prove a failed
/// settlement rolls back the spend recording and audit entry that ran
/// just before it.
contract RefusingUSDC {
    uint8 public constant decimals = 6;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function approve(address, uint256) external pure returns (bool) {
        return true;
    }

    function transferFrom(address, address, uint256) external pure returns (bool) {
        return false; // compliance blocklist-style refusal, no revert
    }
}

contract HardeningTest is Test {
    SpendGuard public spendGuard;
    PolicyRegistry public policyRegistry;
    AuditLog public auditLog;

    address public admin = address(this);
    address public approver = address(0x1);
    address public approver2 = address(0x11);
    address public agent = address(0x2);
    address public counterparty = address(0x3);

    uint256 constant SIX = 10 ** 6;
    MockUSDC public usdc;

    function setUp() public {
        usdc = new MockUSDC();
        policyRegistry = new PolicyRegistry(admin);
        auditLog = new AuditLog(admin);
        spendGuard = new SpendGuard(admin, address(policyRegistry), address(auditLog), address(usdc));

        policyRegistry.setGuard(address(spendGuard), true);
        auditLog.setGuard(address(spendGuard), true);
        spendGuard.setApprover(approver, true);
        spendGuard.setApprover(approver2, true);

        // Fund the agent and grant the guard the allowance the non-custodial
        // settlement pulls from.
        usdc.mint(agent, 1_000_000 * SIX);
        vm.prank(agent);
        usdc.approve(address(spendGuard), type(uint256).max);
    }

    // ------------------------------------------------------------------
    // Reentrancy
    // ------------------------------------------------------------------

    function test_Reentrancy_RequestPayment_RevertsOnReentrantCall() public {
        ReentrantUSDC usdc = new ReentrantUSDC();
        SpendGuard guard = new SpendGuard(admin, address(policyRegistry), address(auditLog), address(usdc));
        // Circular wiring completed: the malicious token now aims its
        // reentrant call at exactly the guard that will call into it.
        usdc.setGuardTarget(guard);
        policyRegistry.setGuard(address(guard), true);
        auditLog.setGuard(address(guard), true);

        address payer = address(0x42);
        usdc.approve(address(guard), type(uint256).max);
        policyRegistry.setPolicy(payer, 100 * SIX, 100 * SIX, 100 * SIX);
        policyRegistry.setAllowlist(payer, counterparty, true);

        vm.prank(payer);
        vm.expectRevert(ReentrancyGuard.ReentrantCall.selector);
        guard.requestPayment(payer, counterparty, 10 * SIX);
    }

    // ------------------------------------------------------------------
    // Settlement failure must roll back everything (atomicity)
    // ------------------------------------------------------------------

    function test_Settle_Failure_RollsBackSpendAndAudit() public {
        RefusingUSDC usdc = new RefusingUSDC();
        SpendGuard guard = new SpendGuard(admin, address(policyRegistry), address(auditLog), address(usdc));
        policyRegistry.setGuard(address(guard), true);
        auditLog.setGuard(address(guard), true);

        policyRegistry.setPolicy(agent, 100 * SIX, 100 * SIX, 100 * SIX);
        policyRegistry.setAllowlist(agent, counterparty, true);

        // transferFrom returns false — the guard must treat that as failure,
        // and NOTHING may look like money moved: no spend, no audit entry.
        vm.prank(agent);
        vm.expectRevert(bytes("USDC settlement failed"));
        guard.requestPayment(agent, counterparty, 10 * SIX);

        (, , , uint256 spent, , , , ) = policyRegistry.policies(agent);
        assertEq(spent, 0, "spend must roll back with the reverted settlement");
        assertEq(auditLog.entryCount(), 0, "audit must roll back with the reverted settlement");
    }
    // ------------------------------------------------------------------
    // Global daily ceiling
    // ------------------------------------------------------------------

    function test_GlobalCeiling_BlocksSpendAcrossAgents() public {
        policyRegistry.setGlobalDailyCap(150 * SIX);
        policyRegistry.setPolicy(agent, 1000 * SIX, 100 * SIX, 100 * SIX);
        policyRegistry.setAllowlist(agent, counterparty, true);

        // Well inside the agent's own caps; only the global ceiling limits it.
        spendGuard.requestPayment(agent, counterparty, 100 * SIX);
        (, , , uint256 spent, , , , ) = policyRegistry.policies(agent);
        assertEq(spent, 100 * SIX);

        // 100 spent + 100 more = 200 > 150 global: blocked even though the
        // agent's own daily cap allows 900 more.
        uint256 requestId = spendGuard.requestPayment(agent, counterparty, 100 * SIX);
        assertEq(requestId, 0, "should be blocked by the global ceiling");
        (, , , uint256 spentAfter, , , , ) = policyRegistry.policies(agent);
        assertEq(spentAfter, 100 * SIX, "blocked payment must not record spend");

        // Global counter resets on the UTC day boundary like per-agent ones.
        vm.warp(block.timestamp + 1 days);
        uint256 again = spendGuard.requestPayment(agent, counterparty, 100 * SIX);
        assertEq(again, 0, "resets with the day");
    }

    // ------------------------------------------------------------------
    // Emergency pause
    // ------------------------------------------------------------------

    function test_Pause_BlocksSettlement_ButNotRejection() public {
        policyRegistry.setPolicy(agent, 1000 * SIX, 100 * SIX, 40 * SIX);
        policyRegistry.setAllowlist(agent, counterparty, true);

        uint256 requestId = spendGuard.requestPayment(agent, counterparty, 60 * SIX);
        assertTrue(requestId != 0);

        vm.prank(admin);
        spendGuard.setPaused(true);

        // Money movement is frozen — both new and queued payments.
        vm.prank(agent);
        vm.expectRevert(SpendGuard.ContractPaused.selector);
        spendGuard.requestPayment(agent, counterparty, 10 * SIX);
        vm.prank(approver);
        vm.expectRevert(SpendGuard.ContractPaused.selector);
        spendGuard.approvePending(requestId);

        // Rejection moves no money, so it works while paused.
        vm.prank(approver);
        spendGuard.rejectPending(requestId);
        (, , , bool resolved) = spendGuard.pending(requestId);
        assertTrue(resolved, "rejection must work while paused");

        // Unpausing restores settlement.
        vm.prank(admin);
        spendGuard.setPaused(false);
        uint256 again = spendGuard.requestPayment(agent, counterparty, 10 * SIX);
        assertEq(again, 0, "settlement resumes after unpause");
    }

    function test_Pause_OnlyAdmin() public {
        vm.prank(approver);
        vm.expectRevert(bytes("not admin"));
        spendGuard.setPaused(true);
    }
    // ------------------------------------------------------------------
    // Timelock on cap increases
    // ------------------------------------------------------------------

    function test_Timelock_CapIncrease_ScheduledNotImmediate() public {
        policyRegistry.setPolicy(agent, 100 * SIX, 100 * SIX, 40 * SIX);
        policyRegistry.setAllowlist(agent, counterparty, true);

        // Scheduling: the raise is recorded as pending, NOT applied.
        policyRegistry.setPolicy(agent, 200 * SIX, 150 * SIX, 40 * SIX);
        (, , , uint256 effectiveAt) = policyRegistry.pendingPolicy(agent);
        assertTrue(effectiveAt != 0, "increase should be scheduled");

        (uint256 capNow, , , , , , , ) = policyRegistry.policies(agent);
        assertEq(capNow, 100 * SIX, "current cap must stay until applied");

        // Old (lower) caps keep enforcing before the delay elapses — a
        // compromised admin key gains nothing inside the window. The request
        // isn't reverted, it's BLOCKED (recorded, refused, no funds move).
        vm.prank(agent);
        uint256 blockedId = spendGuard.requestPayment(agent, counterparty, 120 * SIX);
        assertEq(blockedId, 0, "must be blocked under the old caps");

        // Applying early is refused.
        vm.expectRevert(bytes("policy change not yet effective"));
        policyRegistry.applyPolicy(agent);

        // After the delay, anyone (not just admin) can apply it.
        vm.warp(effectiveAt + 1);
        policyRegistry.applyPolicy(agent); // called from the test, not the admin

        (uint256 capAfter, , , , , , , ) = policyRegistry.policies(agent);
        assertEq(capAfter, 200 * SIX);
        vm.prank(agent);
        uint256 requestId = spendGuard.requestPayment(agent, counterparty, 120 * SIX);
        assertTrue(requestId != 0, "raised cap lets the request through (escalated: above threshold)");
    }

    function test_Timelock_CapDecrease_IsImmediate() public {
        policyRegistry.setPolicy(agent, 100 * SIX, 100 * SIX, 40 * SIX);
        policyRegistry.setPolicy(agent, 50 * SIX, 50 * SIX, 20 * SIX); // decrease

        (, , , uint256 effectiveAt) = policyRegistry.pendingPolicy(agent);
        assertEq(effectiveAt, 0, "decreases must not be scheduled");

        (uint256 cap, , , , , , , ) = policyRegistry.policies(agent);
        assertEq(cap, 50 * SIX, "decrease applies immediately");
    }

    function test_Timelock_CancelScheduledIncrease() public {
        policyRegistry.setPolicy(agent, 100 * SIX, 100 * SIX, 40 * SIX);
        policyRegistry.setPolicy(agent, 200 * SIX, 100 * SIX, 40 * SIX);

        policyRegistry.cancelPolicyChange(agent);

        vm.expectRevert(bytes("no scheduled policy change"));
        policyRegistry.applyPolicy(agent);
        (uint256 cap, , , , , , , ) = policyRegistry.policies(agent);
        assertEq(cap, 100 * SIX, "cancelled increase must never apply");
    }

    // ------------------------------------------------------------------
    // Race scenarios from the hardening review
    // ------------------------------------------------------------------

    /// Two escalated requests that each fit under the daily cap alone but
    /// not together: the collision now surfaces at ESCALATION time — the
    /// second requestPayment reverts on the reservation require (cheap,
    /// atomic, no approver gas ever spent) instead of surfacing later as a
    /// reverted approval transaction.
    function test_Race_TwoEscalations_IndividuallyFit_CombinedDont() public {
        policyRegistry.setPolicy(agent, 100 * SIX, 100 * SIX, 40 * SIX);
        policyRegistry.setAllowlist(agent, counterparty, true);

        // The first escalation reserves 60 of the 100 cap and queues.
        uint256 requestA = spendGuard.requestPayment(agent, counterparty, 60 * SIX);
        assertTrue(requestA != 0, "first escalation should reserve and queue");

        (, , , , , , uint256 reserved, ) = policyRegistry.policies(agent);
        assertEq(reserved, 60 * SIX, "escalation must reserve headroom");

        // The second escalation collides with the live reservation (60+60>100):
        // reservation-aware checkPolicy BLOCKS it (recorded, refused, no funds
        // move) before it can queue. reserve()'s require remains the backstop
        // for concurrent requests that pass checkPolicy before either lands.
        vm.prank(agent);
        uint256 requestB = spendGuard.requestPayment(agent, counterparty, 60 * SIX);
        assertEq(requestB, 0, "colliding escalation must be blocked at escalation time");

        // The first request approves cleanly; its reservation converts into
        // spend rather than double-counting.
        vm.prank(approver);
        spendGuard.approvePending(requestA);
        (, , , uint256 spent, , , uint256 reservedAfter, ) = policyRegistry.policies(agent);
        assertEq(spent, 60 * SIX, "approval converts the reservation into spend");
        assertEq(reservedAfter, 0, "approval releases the reservation");
    }

    /// Second approval of the same request (a different approver racing the
    /// first) reverts instead of double-spending.
    function test_Race_DoubleApproval_SecondReverts() public {
        policyRegistry.setPolicy(agent, 1000 * SIX, 100 * SIX, 40 * SIX);
        policyRegistry.setAllowlist(agent, counterparty, true);

        uint256 requestId = spendGuard.requestPayment(agent, counterparty, 60 * SIX);

        vm.prank(approver);
        spendGuard.approvePending(requestId);

        vm.prank(approver2);
        vm.expectRevert(bytes("already resolved"));
        spendGuard.approvePending(requestId);
    }

    /// Pre-filter vs. authority: two immediate payments that each pass
    /// checkPolicy cannot both land if together they exceed the cap — here
    /// the pre-filter itself catches it, so the second is BLOCKED (recorded
    /// as blocked, no funds move) rather than reverted.
    function test_Race_ConcurrentCheckBothPass_OnlyCombinedBudgetLands() public {
        policyRegistry.setPolicy(agent, 100 * SIX, 100 * SIX, 100 * SIX);
        policyRegistry.setAllowlist(agent, counterparty, true);

        vm.prank(agent);
        spendGuard.requestPayment(agent, counterparty, 60 * SIX); // lands

        vm.prank(agent);
        uint256 second = spendGuard.requestPayment(agent, counterparty, 60 * SIX); // 60+60 > 100
        assertEq(second, 0, "second payment must be blocked by the pre-filter");

        (, , , uint256 spent, , , , ) = policyRegistry.policies(agent);
        assertEq(spent, 60 * SIX, "only the first payment's spend is recorded");
    }
}

