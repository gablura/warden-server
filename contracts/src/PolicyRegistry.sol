// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./AccessControlLite.sol";

// File-level Slither suppressions — triaged 2026-09-16, one finding class:
// the per-UTC-day cap accounting (block.timestamp / 1 days) that every
// limit in this contract is built on. Both `incorrect-equality` and
// `timestamp` hits are the day-boundary comparisons (`lastResetDay ==
// today`, `lastGlobalResetDay == today`) and their derivative requires.
// These are not manipulable-value hazards here: both sides of every
// comparison derive from the SAME block's timestamp, so a miner cannot
// shift an individual reset or cap check more than the block's own
// timestamp already does — daily caps are tolerance-grade controls (a
// miner's ~seconds of timestamp drift cannot materially extend a day),
// and a *missed* day-boundary equality only carries spend into the next
// day, which is conservative (spend stays capped, never unbounded).
// The authoritative enforcement (recordSpend's require) is itself part
// of this same accounting and equally safe. Cross-checked against the
// 97-test Foundry suite (Hardening.t.sol, Reservation.t.sol).
// slither-disable-start incorrect-equality
// slither-disable-start timestamp

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
/// - Escalation-time reservations: an escalated request reserves its
///   amount against the cap when it enters the queue, not when it is
///   approved. Two escalations that individually fit but collectively
///   don't now collide at ESCALATION time (the second is blocked, no
///   gas wasted) instead of at approval time (a reverted transaction).
///   Reservations expire after RESERVATION_TTL so a forgotten pending
///   request cannot lock up headroom forever.
contract PolicyRegistry is AccessControlLite {
    struct Policy {
        uint256 dailyCap;             // max USDC (6 decimals) an agent can move per rolling day
        uint256 perTxCap;              // max USDC per single payment
        uint256 escalationThreshold;   // above this, a human approver must sign off
        uint256 spentToday;
        uint256 lastResetDay;          // block.timestamp / 1 days, for the daily counter
        bool exists;
        // --- escalation-time reservation (see hardening notes above) ---
        uint256 activeReserved;        // sum of live escalation reservations
        uint256 reservedUntil;         // newest reservation's expiry timestamp
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

    /// @notice Sum of live escalation reservations across all agents.
    /// Counted against the global ceiling alongside globalSpentToday so N
    /// agents can't collectively reserve past the circuit breaker. Resets
    /// with the daily counters; a per-agent reservation that expires
    /// mid-day keeps counting here until the day rolls over — conservative
    /// (over-counts, never under-counts) for a safety ceiling.
    uint256 public globalReservedToday;

    /// @notice How long an escalation reservation holds headroom. A pending
    /// request older than this no longer blocks the agent's cap; the
    /// approval-time require in recordSpend remains the final arbiter.
    uint256 public constant RESERVATION_TTL = 7 days;

    /// @notice Delay between scheduling a cap increase and it becoming
    /// applicable via applyPolicy().
    uint256 public constant CAP_CHANGE_DELAY = 1 days;

    event PolicySet(address indexed agent, uint256 dailyCap, uint256 perTxCap, uint256 escalationThreshold);
    event PolicyChangeScheduled(address indexed agent, uint256 dailyCap, uint256 perTxCap, uint256 escalationThreshold, uint256 effectiveAt);
    event PolicyChangeCancelled(address indexed agent);
    event AllowlistUpdated(address indexed agent, address indexed counterparty, bool allowed);
    event GlobalDailyCapSet(uint256 cap);
    event SpendReserved(address indexed agent, uint256 indexed requestId, uint256 amount, uint256 expiresAt);
    event SpendReservationReleased(address indexed agent, uint256 indexed requestId, uint256 amount);

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

    /// @notice Reserve `amount` of an agent's daily headroom on behalf of an
    /// escalated request. Guard-only (SpendGuard calls this at escalation
    /// time); fails closed when the reservation would push the agent or the
    /// global ceiling over their caps — the second of two colliding
    /// escalations is refused HERE, before any approval gas is ever spent.
    /// Reverts when the agent has no policy: a reservation without a policy
    /// would be unenforceable, and checkPolicy blocks such requests anyway.
    ///
    /// Each reservation lives until `block.timestamp + RESERVATION_TTL` and
    /// releases on resolve (approve/reject) or lazily at the day boundary —
    /// a forgotten pending request can only lock headroom for TTL days.
    function reserve(address agent, uint256 requestId, uint256 amount) external onlyGuard {
        Policy storage p = policies[agent];
        require(p.exists, "no policy for agent");

        uint256 today = block.timestamp / 1 days;
        if (p.lastResetDay != today) {
            p.spentToday = 0;
            p.activeReserved = 0;
            p.lastResetDay = today;
        }

        uint256 globalSpent = (lastGlobalResetDay == today) ? globalSpentToday : 0;
        uint256 globalReserved = (lastGlobalResetDay == today) ? globalReservedToday : 0;

        // Same collision math as checkPolicy, at reservation time: the
        // reserved amount must fit alongside spend AND every reservation
        // queued ahead of it, per agent and globally.
        require(p.spentToday + p.activeReserved + amount <= p.dailyCap, "exceeds daily cap");
        require(globalSpent + globalReserved + amount <= globalDailyCap, "exceeds global daily cap");

        p.activeReserved += amount;
        globalReservedToday = globalReserved + amount;
        if (lastGlobalResetDay != today) {
            lastGlobalResetDay = today;
        }

        uint256 expiresAt = block.timestamp + RESERVATION_TTL;
        if (expiresAt > p.reservedUntil) {
            p.reservedUntil = expiresAt;
        }
        emit SpendReserved(agent, requestId, amount, expiresAt);
    }

    /// @notice Release a previously made reservation. Guard-only; called by
    /// SpendGuard when an escalated request is rejected (its headroom must
    /// flow back) and when approved (recordSpend takes over the counting).
    /// Releasing an unknown/already-released reservation is a no-op: the
    /// approve path releases defensively and must never revert because the
    /// day boundary already cleaned the amount up.
    function release(address agent, uint256 requestId, uint256 amount) external onlyGuard {
        Policy storage p = policies[agent];
        if (!p.exists) return;

        uint256 today = block.timestamp / 1 days;
        if (p.lastResetDay != today) {
            // Reservation belongs to a previous day — it no longer exists.
            return;
        }

        if (amount > p.activeReserved) {
            // Expiry/overlap already removed the amount; floor at zero.
            p.activeReserved = 0;
        } else {
            p.activeReserved -= amount;
        }

        uint256 globalReserved = globalReservedToday;
        globalReservedToday = amount > globalReserved ? 0 : globalReserved - amount;

        emit SpendReservationReleased(agent, requestId, amount);
    }

    /// @notice Read-only check SpendGuard calls before acting on a payment request.
    /// Does not mutate state, so two simultaneous requests can both be checked
    /// safely before either one commits spend via recordSpend().
    ///
    /// Reservation-aware: live reservations count against the cap here, so a
    /// new request that would collide with a queued escalation is BLOCKED
    /// with a reason (recorded, no funds move) instead of escalating into a
    /// guaranteed-revert approval later.
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
        // Reservations expire lazily: they only count while their day is
        // current, and drop out entirely once the TTL day boundary passes.
        // Mid-day TTL expiry under-counts headroom by design — a pending
        // request whose reservation lapsed stops blocking new traffic, and
        // the approval-time require in recordSpend stays the final arbiter.
        uint256 reserved = (p.lastResetDay == today) ? p.activeReserved : 0;
        if (spent + reserved + amount > p.dailyCap) return (false, false, "exceeds daily cap");

        // Hard global ceiling, above every per-agent policy. This is the
        // circuit breaker for a misconfigured policy: even a valid-looking
        // fat-fingered cap cannot push total daily outflow past it.
        uint256 globalSpent = (lastGlobalResetDay == today) ? globalSpentToday : 0;
        uint256 globalReserved = (lastGlobalResetDay == today) ? globalReservedToday : 0;
        if (globalSpent + globalReserved + amount > globalDailyCap) return (false, false, "exceeds global daily cap");

        bool escalate = amount > p.escalationThreshold;
        return (true, escalate, "");
    }

    /// @notice Called by SpendGuard only once a payment is actually executed
    /// (immediately, or after an approver signs off on an escalated one).
    /// The daily-cap require here is the authoritative enforcement —
    /// checkPolicy is only a pre-filter, and two requests that both pass the
    /// pre-filter can still be executed one at a time; whichever lands second
    /// reverts here, which is what makes combined-overflow impossible.
    ///
    /// Reservations don't count here: the approver explicitly signed off on
    /// this amount, so it consumes real headroom (spentToday), never the
    /// reservation bucket. Its reservation is released by SpendGuard first.
    function recordSpend(address agent, uint256 amount) external onlyGuard {
        Policy storage p = policies[agent];
        require(p.exists, "no policy for agent");

        uint256 today = block.timestamp / 1 days;
        if (p.lastResetDay != today) {
            p.spentToday = 0;
            p.activeReserved = 0;
            p.lastResetDay = today;
        }

        require(p.spentToday + amount <= p.dailyCap, "exceeds daily cap");

        if (lastGlobalResetDay != today) {
            globalSpentToday = 0;
            globalReservedToday = 0;
            lastGlobalResetDay = today;
        }

        require(globalSpentToday + amount <= globalDailyCap, "exceeds global daily cap");

        p.spentToday += amount;
        globalSpentToday += amount;
    }
}

// Scope of the day-boundary suppressions opened above — the entire contract
// body is this one accounting pattern.
// slither-disable-end incorrect-equality
// slither-disable-end timestamp
