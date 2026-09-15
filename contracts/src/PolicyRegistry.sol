// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./AccessControlLite.sol";

/// @notice Source of truth for what each AI agent is allowed to spend.
/// SpendGuard reads this before moving any USDC, and writes back to it
/// only once a payment actually settles.
///
/// Hardening (pre-mainnet):
/// - Global daily ceiling independent of any agent's policy — protects
///   against a misconfigured per-agent policy (a fat-fingered perTxCap,
///   an admin mistake) draining more than an absolute maximum in a day.
/// - Timelock on policy cap INCREASES: an admin-key compromise can no
///   longer instantly raise every agent's cap and drain funds in the
///   same block; the increase sits pending for CAP_CHANGE_DELAY, giving
///   monitoring a window to catch it. Decreases and brand-new policies
///   apply immediately — tightening must never have to wait, and a
///   first policy isn't an increase of anything.
contract PolicyRegistry is AccessControlLite {
    struct Policy {
        uint256 dailyCap;             // max USDC (6 decimals) an agent can move per rolling day
        uint256 perTxCap;              // max USDC per single payment
        uint256 escalationThreshold;   // above this, a human approver must sign off
        uint256 spentToday;
        uint256 lastResetDay;          // block.timestamp / 1 days, for the daily counter
        bool exists;
    }

    /// @notice A scheduled cap increase. Inert until effectiveAt passes and
    /// anyone calls applyPolicy(); until then checkPolicy/recordSpend keep
    /// enforcing the CURRENT (lower) caps — fail-closed by construction.
    struct PendingPolicy {
        uint256 dailyCap;
        uint256 perTxCap;
        uint256 escalationThreshold;
        uint256 effectiveAt;
    }

    mapping(address => Policy) public policies;
    mapping(address => PendingPolicy) public pendingPolicy;
    mapping(address => mapping(address => bool)) public allowlist; // agent => counterparty => ok

    /// @notice Absolute per-day spend ceiling across ALL agents. Starts
    /// unlimited; the admin is expected to set a concrete value at deploy
    /// configuration time.
    uint256 public globalDailyCap = type(uint256).max;
    uint256 public globalSpentToday;
    uint256 public lastGlobalResetDay;

    /// @notice Delay between scheduling a cap increase and it becoming
    /// applicable via applyPolicy().
    uint256 public constant CAP_CHANGE_DELAY = 1 days;

    event PolicySet(address indexed agent, uint256 dailyCap, uint256 perTxCap, uint256 escalationThreshold);
    event PolicyChangeScheduled(address indexed agent, uint256 dailyCap, uint256 perTxCap, uint256 escalationThreshold, uint256 effectiveAt);
    event PolicyChangeCancelled(address indexed agent);
    event AllowlistUpdated(address indexed agent, address indexed counterparty, bool allowed);
    event GlobalDailyCapSet(uint256 cap);

    constructor(address admin_) AccessControlLite(admin_) {}

    function setGlobalDailyCap(uint256 cap) external onlyAdmin {
        globalDailyCap = cap;
        emit GlobalDailyCapSet(cap);
    }

    function setPolicy(
        address agent,
        uint256 dailyCap,
        uint256 perTxCap,
        uint256 escalationThreshold
    ) external onlyAdmin {
        require(perTxCap <= dailyCap, "perTxCap exceeds dailyCap");
        require(escalationThreshold <= perTxCap, "threshold exceeds perTxCap");

        Policy storage p = policies[agent];

        // A brand-new policy has no cap to raise — apply immediately.
        // Same for any change that does not raise dailyCap (tightening must
        // never be delayed). Only genuine cap increases pay the timelock.
        if (p.exists && dailyCap > p.dailyCap) {
            pendingPolicy[agent] = PendingPolicy(dailyCap, perTxCap, escalationThreshold, block.timestamp + CAP_CHANGE_DELAY);
            emit PolicyChangeScheduled(agent, dailyCap, perTxCap, escalationThreshold, block.timestamp + CAP_CHANGE_DELAY);
            return;
        }

        _applyPolicy(agent, dailyCap, perTxCap, escalationThreshold);
    }

    /// @notice Anyone may materialize a scheduled cap increase once its
    /// delay has elapsed — no privileged call needed for the timelock to
    /// eventually take effect, so a lost admin key can't strand a change.
    function applyPolicy(address agent) external {
        PendingPolicy storage pp = pendingPolicy[agent];
        require(pp.effectiveAt != 0, "no scheduled policy change");
        require(block.timestamp >= pp.effectiveAt, "policy change not yet effective");

        _applyPolicy(agent, pp.dailyCap, pp.perTxCap, pp.escalationThreshold);
        delete pendingPolicy[agent];
    }

    /// @notice Admin escape hatch: revoke a scheduled increase before it
    /// becomes applicable (e.g. it was fat-fingered or made under
    /// compromise and monitoring caught it inside the delay window).
    function cancelPolicyChange(address agent) external onlyAdmin {
        require(pendingPolicy[agent].effectiveAt != 0, "no scheduled policy change");
        delete pendingPolicy[agent];
        emit PolicyChangeCancelled(agent);
    }

    function _applyPolicy(address agent, uint256 dailyCap, uint256 perTxCap, uint256 escalationThreshold) internal {
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

        // Hard global ceiling, above every per-agent policy. This is the
        // circuit breaker for a misconfigured policy: even a valid-looking
        // fat-fingered cap cannot push total daily outflow past it.
        uint256 globalSpent = (lastGlobalResetDay == today) ? globalSpentToday : 0;
        if (globalSpent + amount > globalDailyCap) return (false, false, "exceeds global daily cap");

        bool escalate = amount > p.escalationThreshold;
        return (true, escalate, "");
    }

    /// @notice Called by SpendGuard only once a payment is actually executed
    /// (immediately, or after an approver signs off on an escalated one).
    /// The daily-cap require here is the authoritative enforcement —
    /// checkPolicy is only a pre-filter, and two requests that both pass the
    /// pre-filter can still be executed one at a time; whichever lands second
    /// reverts here, which is what makes combined-overflow impossible.
    function recordSpend(address agent, uint256 amount) external onlyGuard {
        Policy storage p = policies[agent];
        require(p.exists, "no policy for agent");

        uint256 today = block.timestamp / 1 days;
        if (p.lastResetDay != today) {
            p.spentToday = 0;
            p.lastResetDay = today;
        }

        require(p.spentToday + amount <= p.dailyCap, "exceeds daily cap");

        if (lastGlobalResetDay != today) {
            globalSpentToday = 0;
            lastGlobalResetDay = today;
        }

        require(globalSpentToday + amount <= globalDailyCap, "exceeds global daily cap");

        p.spentToday += amount;
        globalSpentToday += amount;
    }
}
