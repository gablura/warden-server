// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Minimal reentrancy protection, dependency-free like the rest of
/// this codebase (the OZ-shaped boolean is the cheapest form that is also
/// obvious to audit). Sets an entering flag around the guarded function;
/// any reentrant call — including via a malicious counterparty contract
/// reached through USDC's transferFrom — reverts.
abstract contract ReentrancyGuard {
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;

    uint256 private _status = _NOT_ENTERED;

    error ReentrantCall();

    modifier nonReentrant() {
        if (_status == _ENTERED) revert ReentrantCall();
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }
}
