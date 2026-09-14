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

/// @notice The gate every agent payment passes through. Deploy this as
/// the SpendGuard, register it as a guard on both PolicyRegistry and
/// AuditLog (setGuard), and have agents (or the agent's wallet/relayer)
/// call requestPayment() instead of transferring USDC directly.
contract SpendGuard is AccessControlLite {
    IPolicyRegistry public registry;
    IAuditLog public auditLog;

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

    constructor(address admin_, address registry_, address auditLog_) AccessControlLite(admin_) {
        registry = IPolicyRegistry(registry_);
        auditLog = IAuditLog(auditLog_);
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
        _settle(counterparty, amount);
        auditLog.record(agent, counterparty, amount, "approved");
        emit PaymentApproved(0, agent, counterparty, amount);
        return 0;
    }

    function approvePending(uint256 requestId) external onlyApprover {
        PendingRequest storage r = pending[requestId];
        require(!r.resolved, "already resolved");
        r.resolved = true;

        registry.recordSpend(r.agent, r.amount);
        _settle(r.counterparty, r.amount);
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

    /// @dev Placeholder for actual USDC movement. On Arc, wire this to
    /// whichever settlement path you pick: direct ERC20 transfer if this
    /// contract holds custody of agent funds, or a call into a paymaster /
    /// Circle programmable wallet if agents keep custody themselves.
    function _settle(address counterparty, uint256 amount) internal {
        // TODO: integrate USDC transfer or Circle programmable wallet call.
    }
}
