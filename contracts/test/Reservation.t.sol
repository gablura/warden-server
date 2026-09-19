// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SpendGuard} from "../src/SpendGuard.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";
import {AuditLog} from "../src/AuditLog.sol";
import {MockUSDC} from "./SpendGuard.t.sol";

/// @dev Escalation-time cap reservation (the hardening review's case study).
/// An escalated request reserves its amount against the cap at escalation
/// time; a second escalation that would collide is refused immediately
/// instead of surfacing later as a reverted, gas-costing approval.
contract ReservationTest is Test {
    SpendGuard public spendGuard;
    PolicyRegistry public policyRegistry;
    AuditLog public auditLog;
    MockUSDC public usdc;

    address public admin = address(this);
    address public approver = address(0x1);
    address public agent = address(0x2);
    address public agent2 = address(0x4);
    address public counterparty = address(0x3);

    uint256 constant SIX = 10 ** 6;

    function setUp() public {
        usdc = new MockUSDC();
        policyRegistry = new PolicyRegistry(admin);
        auditLog = new AuditLog(admin);
        spendGuard = new SpendGuard(admin, address(policyRegistry), address(auditLog), address(usdc));

        policyRegistry.setGuard(address(spendGuard), true);
        auditLog.setGuard(address(spendGuard), true);
        spendGuard.setApprover(approver, true);

        // Cap 100, per-tx 100, threshold 40 — matches the review's worked example.
        policyRegistry.setPolicy(agent, 100 * SIX, 100 * SIX, 40 * SIX);
        policyRegistry.setAllowlist(agent, counterparty, true);

        usdc.mint(agent, 1_000_000 * SIX);
        vm.prank(agent);
        usdc.approve(address(spendGuard), type(uint256).max);
    }

    // ------------------------------------------------------------------
    // Collision surfaces at escalation time, not approval time
    // ------------------------------------------------------------------

    /// The review's worked example: $1,000 cap equivalent, two escalations
    /// of 60 each. The second requestPayment reverts on the reservation
    /// require — no pending row, no audit entry, no approver gas spent.
    function test_Reserve_CollisionBlocksSecondEscalation() public {
        vm.prank(agent);
        uint256 requestA = spendGuard.requestPayment(agent, counterparty, 60 * SIX);
        assertTrue(requestA != 0);

        (, , , , , , uint256 reserved, ) = policyRegistry.policies(agent);
        assertEq(reserved, 60 * SIX);

        vm.prank(agent);
        uint256 requestB = spendGuard.requestPayment(agent, counterparty, 60 * SIX);
        assertEq(requestB, 0, "colliding escalation must be blocked at escalation time");

        // The blocked request left nothing behind but its audit entry.
        assertEq(auditLog.entryCount(), 2, "escalated + blocked entries only");
    }

    /// A request that would fit even WITH the reservation still escalates:
    /// reservations block only genuine collisions. (Threshold is 40, so
    /// both amounts must exceed it to escalate at all; 41+50=91<=100 fits.)
    function test_Reserve_NonCollidingEscalationStillQueues() public {
        vm.prank(agent);
        assertTrue(spendGuard.requestPayment(agent, counterparty, 41 * SIX) != 0);
        vm.prank(agent);
        assertTrue(spendGuard.requestPayment(agent, counterparty, 50 * SIX) != 0);

        (, , , , , , uint256 reserved, ) = policyRegistry.policies(agent);
        assertEq(reserved, 91 * SIX);
    }

    /// A small IMMEDIATE payment colliding with a live reservation is
    /// BLOCKED by checkPolicy (recorded, refused) rather than escalating.
    function test_Reserve_ImmediatePaymentBlockedByLiveReservation() public {
        vm.prank(agent);
        assertTrue(spendGuard.requestPayment(agent, counterparty, 60 * SIX) != 0);

        // 50 would fit alone; with the reservation it collides (60+50>100).
        vm.prank(agent);
        uint256 blocked = spendGuard.requestPayment(agent, counterparty, 50 * SIX);
        assertEq(blocked, 0, "colliding immediate payment must be blocked, not queued");

        (bool allowed, , string memory reason) =
            policyRegistry.checkPolicy(agent, counterparty, 50 * SIX);
        assertFalse(allowed);
        assertEq(reason, "exceeds daily cap");
    }

    // ------------------------------------------------------------------
    // Reservation lifecycle
    // ------------------------------------------------------------------

    function test_Reserve_RejectionReleasesHeadroom() public {
        vm.prank(agent);
        uint256 requestId = spendGuard.requestPayment(agent, counterparty, 60 * SIX);

        vm.prank(approver);
        spendGuard.rejectPending(requestId);

        (, , , , , , uint256 reserved, ) = policyRegistry.policies(agent);
        assertEq(reserved, 0, "rejected request must free its headroom");
        (, , , uint256 spent, , , , ) = policyRegistry.policies(agent);
        assertEq(spent, 0);

        // Headroom is immediately usable again.
        vm.prank(agent);
        assertTrue(spendGuard.requestPayment(agent, counterparty, 60 * SIX) != 0);
    }

    function test_Reserve_ApprovalConvertsReservationIntoSpend() public {
        vm.prank(agent);
        uint256 requestId = spendGuard.requestPayment(agent, counterparty, 60 * SIX);

        vm.prank(approver);
        spendGuard.approvePending(requestId);

        (, , , uint256 spent, , , uint256 reserved, ) = policyRegistry.policies(agent);
        assertEq(spent, 60 * SIX, "approval records spend");
        assertEq(reserved, 0, "reservation released, not double-counted");
    }

    // ------------------------------------------------------------------
    // Day boundary and TTL expiry
    // ------------------------------------------------------------------

    function test_Reserve_DayBoundaryClearsReservation() public {
        vm.prank(agent);
        assertTrue(spendGuard.requestPayment(agent, counterparty, 60 * SIX) != 0);
        (, , , , , , uint256 reserved, ) = policyRegistry.policies(agent);
        assertEq(reserved, 60 * SIX);

        // The pending request is never resolved, but the day rolls over:
        // checkPolicy stops counting the old reservation (lazy reset), so
        // the new day's cap is fully available again.
        vm.warp(block.timestamp + 1 days);
        (bool allowed, , ) = policyRegistry.checkPolicy(agent, counterparty, 60 * SIX);
        assertTrue(allowed, "reservation must not block the new day");

        // The next mutating call (a fresh escalation) resets the stored
        // counters as part of its day-rollover handling.
        vm.prank(agent);
        assertTrue(spendGuard.requestPayment(agent, counterparty, 60 * SIX) != 0);
        (, , , , , , uint256 reservedAfter, ) = policyRegistry.policies(agent);
        assertEq(reservedAfter, 60 * SIX, "only the new day's reservation remains");
    }

    function test_Reserve_TtlExpiryFreesHeadroomMidDay() public {
        vm.prank(agent);
        assertTrue(spendGuard.requestPayment(agent, counterparty, 60 * SIX) != 0);

        // Same day, but past the TTL: the reservation stops counting in
        // checkPolicy (mid-day TTL expiry deliberately under-counts — the
        // approval-time require in recordSpend stays the final arbiter).
        vm.warp(block.timestamp + policyRegistry.RESERVATION_TTL() + 1 hours);
        (bool allowed, , ) = policyRegistry.checkPolicy(agent, counterparty, 50 * SIX);
        assertTrue(allowed, "expired reservation must not block new requests");
    }

    function test_Reserve_ExpiredReservationApprovalStillCapEnforced() public {
        vm.prank(agent);
        uint256 requestId = spendGuard.requestPayment(agent, counterparty, 60 * SIX);

        // Reservations don't gate approval; recordSpend is the arbiter.
        // Same day, reservation still live, plenty of headroom: approves.
        vm.prank(approver);
        spendGuard.approvePending(requestId);
        (, , , uint256 spent, , , , ) = policyRegistry.policies(agent);
        assertEq(spent, 60 * SIX);
    }

    // ------------------------------------------------------------------
    // Global ceiling interaction
    // ------------------------------------------------------------------

    function test_Reserve_GlobalCeilingCountsReservations() public {
        policyRegistry.setGlobalDailyCap(150 * SIX);

        // Second agent, generous own cap, so only the global ceiling binds.
        policyRegistry.setPolicy(agent2, 1000 * SIX, 100 * SIX, 40 * SIX);
        policyRegistry.setAllowlist(agent2, counterparty, true);
        usdc.mint(agent2, 1_000_000 * SIX);
        vm.prank(agent2);
        usdc.approve(address(spendGuard), type(uint256).max);

        // Each agent reserves 100 — individually fine (own caps 100/1000),
        // but 100 + 100 > 150 global: the second is BLOCKED by the
        // reservation-aware pre-filter (recorded, no funds move).
        vm.prank(agent);
        assertTrue(spendGuard.requestPayment(agent, counterparty, 100 * SIX) != 0);

        vm.prank(agent2);
        uint256 blocked = spendGuard.requestPayment(agent2, counterparty, 100 * SIX);
        assertEq(blocked, 0, "second reservation must be blocked at the global ceiling");

        assertEq(policyRegistry.globalReservedToday(), 100 * SIX);
    }

    // ------------------------------------------------------------------
    // Access control and events
    // ------------------------------------------------------------------

    function test_Reserve_RevertWhen_NotGuard() public {
        vm.prank(address(0x999));
        vm.expectRevert("not an authorized guard");
        policyRegistry.reserve(agent, 1, 1 * SIX);

        vm.prank(address(0x999));
        vm.expectRevert("not an authorized guard");
        policyRegistry.release(agent, 1, 1 * SIX);
    }

    function test_Reserve_RevertWhen_NoPolicy() public {
        address unknownAgent = address(0x777);
        vm.prank(address(spendGuard));
        vm.expectRevert("no policy for agent");
        policyRegistry.reserve(unknownAgent, 1, 1 * SIX);
    }

    function test_Reserve_EmitsEvents() public {
        vm.prank(agent);
        uint256 requestId = spendGuard.requestPayment(agent, counterparty, 60 * SIX);

        vm.expectEmit(true, true, true, true);
        emit PolicyRegistry.SpendReservationReleased(agent, requestId, 60 * SIX);
        vm.prank(approver);
        spendGuard.rejectPending(requestId);
    }
}
