// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Minimal role management: one admin, a set of human approvers,
/// and a set of "guard" contracts (SpendGuard) allowed to write to
/// PolicyRegistry / AuditLog. Kept dependency-free on purpose so this
/// reads clearly without pulling in OpenZeppelin for a first draft.
contract AccessControlLite {
    address public admin;
    mapping(address => bool) public approvers;
    mapping(address => bool) public guards;

    event AdminTransferred(address indexed previousAdmin, address indexed newAdmin);
    event ApproverUpdated(address indexed approver, bool allowed);
    event GuardUpdated(address indexed guard, bool allowed);

    modifier onlyAdmin() {
        require(msg.sender == admin, "not admin");
        _;
    }

    modifier onlyApprover() {
        require(approvers[msg.sender], "not an approver");
        _;
    }

    modifier onlyGuard() {
        require(guards[msg.sender], "not an authorized guard");
        _;
    }

    constructor(address admin_) {
        require(admin_ != address(0), "admin cannot be zero address");
        admin = admin_;
    }

    function transferAdmin(address newAdmin) external onlyAdmin {
        require(newAdmin != address(0), "admin cannot be zero address");
        emit AdminTransferred(admin, newAdmin);
        admin = newAdmin;
    }

    function setApprover(address approver, bool allowed) external onlyAdmin {
        approvers[approver] = allowed;
        emit ApproverUpdated(approver, allowed);
    }

    function setGuard(address guard, bool allowed) external onlyAdmin {
        guards[guard] = allowed;
        emit GuardUpdated(guard, allowed);
    }
}
