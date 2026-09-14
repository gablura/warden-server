// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./AccessControlLite.sol";

/// @notice Source of truth for what each AI agent is allowed to spend.
/// SpendGuard reads this before moving any USDC, and writes back to it
/// only once a payment actually settles.
contract PolicyRegistry is AccessControlLite {
    struct Policy {
        uint256 dailyCap;             // max USDC (6 decimals) an agent can move per rolling day
        uint256 perTxCap;              // max USDC per single payment
        uint256 escalationThreshold;   // above this, a human approver must sign off
        uint256 spentToday;
        uint256 lastResetDay;          // block.timestamp / 1 days, for the daily counter
        bool exists;
    }

    mapping(address => Policy) public policies;
    mapping(address => mapping(address => bool)) public allowlist; // agent => counterparty => ok

    event PolicySet(address indexed agent, uint256 dailyCap, uint256 perTxCap, uint256 escalationThreshold);
    event AllowlistUpdated(address indexed agent, address indexed counterparty, bool allowed);

    constructor(address admin_) AccessControlLite(admin_) {}

    function setPolicy(
        address agent,
        uint256 dailyCap,
        uint256 perTxCap,
        uint256 escalationThreshold
    ) external onlyAdmin {
        require(perTxCap <= dailyCap, "perTxCap exceeds dailyCap");
        require(escalationThreshold <= perTxCap, "threshold exceeds perTxCap");

        Policy storage p = policies[agent];
        p.dailyCap = dailyCap;
        p.perTxCap = perTxCap;
        p.escalationThreshold = escalationThreshold;
        p.exists = true;

        emit PolicySet(agent, dailyCap, perTxCap, escalationThreshold);
    }

    function setAllowlist(address agent, address counterparty, bool allowed) external onlyAdmin {
        allowlist[agent][counterparty] = allowed;
        emit AllowlistUpdated(agent, counterparty, allowed);
    }

    /// @notice Read-only check SpendGuard calls before acting on a payment request.
    /// Does not mutate state, so two simultaneous requests can both be checked
    /// safely before either one commits spend via recordSpend().
    function checkPolicy(
        address agent,
        address counterparty,
        uint256 amount
    ) external view returns (bool allowed, bool needsApproval, string memory reason) {
        Policy memory p = policies[agent];

        if (!p.exists) return (false, false, "no policy for agent");
        if (!allowlist[agent][counterparty]) return (false, false, "counterparty not allowlisted");
        if (amount > p.perTxCap) return (false, false, "exceeds per-tx cap");

        uint256 today = block.timestamp / 1 days;
        uint256 spent = (p.lastResetDay == today) ? p.spentToday : 0;
        if (spent + amount > p.dailyCap) return (false, false, "exceeds daily cap");

        bool escalate = amount > p.escalationThreshold;
        return (true, escalate, "");
    }

    /// @notice Called by SpendGuard only once a payment is actually executed
    /// (immediately, or after an approver signs off on an escalated one).
    function recordSpend(address agent, uint256 amount) external onlyGuard {
        Policy storage p = policies[agent];
        require(p.exists, "no policy for agent");

        uint256 today = block.timestamp / 1 days;
        if (p.lastResetDay != today) {
            p.spentToday = 0;
            p.lastResetDay = today;
        }

        require(p.spentToday + amount <= p.dailyCap, "exceeds daily cap");
        p.spentToday += amount;
    }
}
