// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./AccessControlLite.sol";

interface IPolicyRegistry {
    function checkPolicy(address agent, address counterparty, uint256 amount)
        external
        view
        returns (bool allowed, bool needsApproval, string memory reason);

    function recordSpend(address agent, uint256 amount) external;
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
contract SpendGuard is AccessControlLite {
    IPolicyRegistry public registry;
    IAuditLog public auditLog;
    /// @notice USDC ERC-20 interface used to settle approved payments.
    IERC20 public immutable usdc;

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

    constructor(address admin_, address registry_, address auditLog_, address usdc_) AccessControlLite(admin_) {
        registry = IPolicyRegistry(registry_);
        auditLog = IAuditLog(auditLog_);
        usdc = IERC20(usdc_);
    }

    /// @notice Entry point for an agent (or its relayer) to move USDC.
    /// Returns 0 if the payment settled immediately or was blocked;
    /// returns a nonzero requestId if it's sitting in the approval queue.
    function requestPayment(address agent, address counterparty, uint256 amount) external returns (uint256 requestId) {
        (bool allowed, bool needsApproval, string memory reason) = registry.checkPolicy(agent, counterparty, amount);

        if (!allowed) {
            auditLog.record(agent, counterparty, amount, string(abi.encodePacked("blocked: ", reason)));
            emit PaymentBlocked(agent, counterparty, amount, reason);
            return 0;
        }

        if (needsApproval) {
            requestId = ++nextRequestId;
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

    function approvePending(uint256 requestId) external onlyApprover {
        PendingRequest storage r = pending[requestId];
        require(!r.resolved, "already resolved");
        r.resolved = true;

        registry.recordSpend(r.agent, r.amount);
        _settle(r.agent, r.counterparty, r.amount);
        auditLog.record(r.agent, r.counterparty, r.amount, "approved-after-escalation");

        emit PendingApproved(requestId, msg.sender);
        emit PaymentApproved(requestId, r.agent, r.counterparty, r.amount);
    }

    function rejectPending(uint256 requestId) external onlyApprover {
        PendingRequest storage r = pending[requestId];
        require(!r.resolved, "already resolved");
        r.resolved = true;

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
