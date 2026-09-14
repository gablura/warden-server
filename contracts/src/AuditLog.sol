// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./AccessControlLite.sol";

/// @notice Immutable record of every spend decision SpendGuard makes.
/// This is the piece that makes Warden useful for compliance exports —
/// every approval, block, and escalation is on-chain and queryable.
contract AuditLog is AccessControlLite {
    struct Entry {
        address agent;
        address counterparty;
        uint256 amount;
        string decision; // "approved" | "blocked: <reason>" | "escalated" | "approved-after-escalation" | "rejected-after-escalation"
        uint256 timestamp;
    }

    Entry[] public entries;

    event Recorded(
        uint256 indexed entryId,
        address indexed agent,
        address indexed counterparty,
        uint256 amount,
        string decision,
        uint256 timestamp
    );

    constructor(address admin_) AccessControlLite(admin_) {}

    function record(
        address agent,
        address counterparty,
        uint256 amount,
        string calldata decision
    ) external onlyGuard {
        entries.push(Entry(agent, counterparty, amount, decision, block.timestamp));
        emit Recorded(entries.length - 1, agent, counterparty, amount, decision, block.timestamp);
    }

    function entryCount() external view returns (uint256) {
        return entries.length;
    }
}
