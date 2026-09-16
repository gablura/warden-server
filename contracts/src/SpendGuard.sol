// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./AccessControlLite.sol";
import "./ReentrancyGuard.sol";

interface IPolicyRegistry {
    function checkPolicy(address agent, address counterparty, uint256 amount)
        external
        view
        returns (bool allowed, bool needsApproval, string memory reason);

    function recordSpend(address agent, uint256 amount) external;

    /// Escalation-time cap reservation (see PolicyRegistry.reserve).
    function reserve(address agent, uint256 requestId, uint256 amount) external;
    function release(address agent, uint256 requestId, uint256 amount) external;
}

interface IAuditLog {
    function record(address agent, address counterparty, uint256 amount, string calldata decision) external;
}

/// @notice Minimal ERC-20 surface used to settle payments. On Arc, USDC is the
/// native asset and is exposed through a canonical ERC-20 interface at
/// 0x3600000000000000000000000000000000000000 with 6 decimals — a standard
/// token that returns a bool from transferFrom, which is all settlement needs.
interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @notice The gate every agent payment passes through. Deploy this as
/// the SpendGuard, register it as a guard on both PolicyRegistry and
/// AuditLog (setGuard), and have agents (or the agent's wallet/relayer)
/// call requestPayment() instead of transferring USDC directly.
///
/// Custody model: non-custodial. SpendGuard never holds agent funds — it is
/// granted a USDC allowance by each agent and pulls settlement straight from
/// the agent's balance to the counterparty. See _settle() below.
///
/// Emergency pause: the admin can freeze all settlement immediately
/// (setPaused) without a redeploy if a bug or exploit is found. Rejections
/// stay possible while paused — emptying the queue is safe and lets
/// approvers clean up during an incident; only money movement freezes.
contract SpendGuard is AccessControlLite, ReentrancyGuard {
    IPolicyRegistry public immutable registry;
    IAuditLog public immutable auditLog;
    /// @notice USDC ERC-20 interface used to settle approved payments.
    IERC20 public immutable usdc;

    bool public paused;

    event PauseSet(bool paused);

    struct PendingRequest {
        address agent;
        address counterparty;
        uint256 amount;
        bool resolved;
    }

    mapping(uint256 => PendingRequest) public pending;
    uint256 public nextRequestId;

    event PaymentApproved(uint256 indexed requestId, address indexed agent, address indexed counterparty, uint256 amount);
    event PaymentBlocked(address indexed agent, address indexed counterparty, uint256 amount, string reason);
    event PaymentEscalated(uint256 indexed requestId, address indexed agent, address indexed counterparty, uint256 amount);
    event PendingApproved(uint256 indexed requestId, address indexed approver);
    event PendingRejected(uint256 indexed requestId, address indexed approver);

    error ContractPaused();

    modifier whenNotPaused() {
        if (paused) revert ContractPaused();
        _;
    }

    constructor(address admin_, address registry_, address auditLog_, address usdc_) AccessControlLite(admin_) {
        registry = IPolicyRegistry(registry_);
        auditLog = IAuditLog(auditLog_);
        usdc = IERC20(usdc_);
    }

    /// @notice Freeze/unfreeze all settlement. Admin-only, immediate.
    function setPaused(bool value) external onlyAdmin {
        paused = value;
        emit PauseSet(value);
    }

    /// @notice Entry point for an agent (or its relayer) to move USDC.
    /// Returns 0 if the payment settled immediately or was blocked;
    /// returns a nonzero requestId if it's sitting in the approval queue.
    ///
    /// nonReentrant: this makes external calls (USDC transferFrom, AuditLog
    /// record), and transferFrom hands control to arbitrary code on
    /// callback-capable tokens — a reentrant requestPayment here could
    /// otherwise double-move funds inside one settlement.
    function requestPayment(address agent, address counterparty, uint256 amount)
        external
        nonReentrant
        whenNotPaused
        returns (uint256 requestId)
    {
        (bool allowed, bool needsApproval, string memory reason) = registry.checkPolicy(agent, counterparty, amount);

        if (!allowed) {
            auditLog.record(agent, counterparty, amount, string(abi.encodePacked("blocked: ", reason)));
            emit PaymentBlocked(agent, counterparty, amount, reason);
            return 0;
        }

        if (needsApproval) {
            requestId = ++nextRequestId;
            // Reserve the amount against the cap NOW, not at approval time:
            // two escalations that individually fit but collectively don't
            // collide here (the second reverts — requestPayment is atomic,
            // so no pending row, no audit entry, no requestId leaks out),
            // instead of surfacing later as a reverted, gas-costing approval.
            registry.reserve(agent, requestId, amount);
            pending[requestId] = PendingRequest(agent, counterparty, amount, false);
            auditLog.record(agent, counterparty, amount, "escalated");
            emit PaymentEscalated(requestId, agent, counterparty, amount);
            return requestId;
        }

        registry.recordSpend(agent, amount);
        _settle(agent, counterparty, amount);
        auditLog.record(agent, counterparty, amount, "approved");
        emit PaymentApproved(0, agent, counterparty, amount);
        return 0;
    }

    /// @notice nonReentrant for the same reason as requestPayment — recordSpend
    /// (registry call) and _settle (USDC transfer) both cross contract
    /// boundaries before this function's effects are fully done. Also paused
    /// with everything else that moves money.
    function approvePending(uint256 requestId) external onlyApprover nonReentrant whenNotPaused {
        PendingRequest storage r = pending[requestId];
        require(!r.resolved, "already resolved");
        r.resolved = true;

        // Hand the reserved headroom over to recordSpend before it checks the
        // cap, or the reservation would double-count against the approval.
        // Defensively released (no-op when the day boundary already cleaned
        // it up); recordSpend's require stays the final arbiter.
        registry.release(r.agent, requestId, r.amount);
        registry.recordSpend(r.agent, r.amount);
        _settle(r.agent, r.counterparty, r.amount);
        auditLog.record(r.agent, r.counterparty, r.amount, "approved-after-escalation");

        emit PendingApproved(requestId, msg.sender);
        emit PaymentApproved(requestId, r.agent, r.counterparty, r.amount);
    }

    /// Deliberately NOT whenNotPaused: rejection moves no money, so it stays
    /// available while paused, letting approvers empty the queue during an
    /// incident instead of leaving requests stranded.
    function rejectPending(uint256 requestId) external onlyApprover nonReentrant {
        PendingRequest storage r = pending[requestId];
        require(!r.resolved, "already resolved");
        r.resolved = true;

        // Rejected requests must not keep holding cap headroom: release the
        // reservation made at escalation time (no-op when it already
        // expired or rolled over at the day boundary).
        registry.release(r.agent, requestId, r.amount);

        auditLog.record(r.agent, r.counterparty, r.amount, "rejected-after-escalation");
        emit PendingRejected(requestId, msg.sender);
    }

    /// @dev Moves USDC from the agent to the counterparty through Arc's USDC
    /// ERC-20 interface (6 decimals, matching the policy amounts in
    /// PolicyRegistry).
    ///
    /// Custody model — non-custodial pull: agents keep their funds and grant
    /// SpendGuard a USDC allowance up front, so the guard is an authorized
    /// spender rather than a custodian. Nothing is ever pooled here, which
    /// keeps per-agent attribution exact and avoids custody risk.
    ///
    /// Fail-closed: if the allowance or balance is insufficient the ERC-20
    /// transfer reverts, reverting the whole request — including the
    /// recordSpend() that ran just before it — so a payment is only ever
    /// recorded as spend once the money has actually moved.
    function _settle(address from, address counterparty, uint256 amount) internal {
        require(usdc.transferFrom(from, counterparty, amount), "USDC settlement failed");
    }
}
