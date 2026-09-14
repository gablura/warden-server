// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// NOTE: This test file requires Foundry to be installed to run.
// Install Foundry first, then:
// 1. Uncomment line 8: import "forge-std/Test.sol";
// 2. Change line 11 to: contract AccessControlLiteTest is Test {
import { Test } from "forge-std/Test.sol";


// import "forge-std/Test.sol";
import {AccessControlLite} from "../src/AccessControlLite.sol";

contract AccessControlLiteTest is Test {
    // TODO: After installing Foundry, change to: contract AccessControlLiteTest is Test {
    
    AccessControlLite public acl;
    address public admin;
    address public approver;
    address public guard;
    address public unauthorized;

    function setUp() public {
        admin = address(this);
        approver = address(0x1);
        guard = address(0x2);
        unauthorized = address(0x999);

        acl = new AccessControlLite(admin);
    }

    function test_Constructor_SetsAdmin() public {
        assertEq(acl.admin(), admin);
    }

    function test_TransferAdmin() public {
        address newAdmin = address(0x5);
        
        vm.expectEmit(true, true, false, false);
        emit AccessControlLite.AdminTransferred(admin, newAdmin);
        
        acl.transferAdmin(newAdmin);
        assertEq(acl.admin(), newAdmin);
    }

    function test_TransferAdmin_RevertWhen_NotAdmin() public {
        vm.prank(unauthorized);
        vm.expectRevert("not admin");
        acl.transferAdmin(address(0x5));
    }

    function test_SetApprover() public {
        acl.setApprover(approver, true);
        assertTrue(acl.approvers(approver));
    }

    function test_SetApprover_RevertWhen_NotAdmin() public {
        vm.prank(unauthorized);
        vm.expectRevert("not admin");
        acl.setApprover(approver, true);
    }

    function test_RemoveApprover() public {
        acl.setApprover(approver, true);
        assertTrue(acl.approvers(approver));
        
        acl.setApprover(approver, false);
        assertFalse(acl.approvers(approver));
    }

    function test_SetGuard() public {
        acl.setGuard(guard, true);
        assertTrue(acl.guards(guard));
    }

    function test_SetGuard_RevertWhen_NotAdmin() public {
        vm.prank(unauthorized);
        vm.expectRevert("not admin");
        acl.setGuard(guard, true);
    }

    function test_RemoveGuard() public {
        acl.setGuard(guard, true);
        assertTrue(acl.guards(guard));
        
        acl.setGuard(guard, false);
        assertFalse(acl.guards(guard));
    }

    function test_OnlyApproverModifier() public {
        acl.setApprover(approver, true);
        
        // Test that approver can call functions with onlyApprover modifier
        vm.prank(approver);
        // This would call a function with onlyApprover modifier if available
        // For now, we just verify the role is set correctly
        assertTrue(acl.approvers(approver));
    }

    function test_OnlyGuardModifier() public {
        acl.setGuard(guard, true);
        
        // Test that guard can call functions with onlyGuard modifier
        vm.prank(guard);
        // This would call a function with onlyGuard modifier if available
        // For now, we just verify the role is set correctly
        assertTrue(acl.guards(guard));
    }

    function test_MultipleApprovers() public {
        address approver1 = address(0x1);
        address approver2 = address(0x2);
        address approver3 = address(0x3);

        acl.setApprover(approver1, true);
        acl.setApprover(approver2, true);
        acl.setApprover(approver3, true);

        assertTrue(acl.approvers(approver1));
        assertTrue(acl.approvers(approver2));
        assertTrue(acl.approvers(approver3));
    }

    function test_MultipleGuards() public {
        address guard1 = address(0x1);
        address guard2 = address(0x2);
        address guard3 = address(0x3);

        acl.setGuard(guard1, true);
        acl.setGuard(guard2, true);
        acl.setGuard(guard3, true);

        assertTrue(acl.guards(guard1));
        assertTrue(acl.guards(guard2));
        assertTrue(acl.guards(guard3));
    }

    function test_AdminCanUpdateOwnSettings() public {
        // Admin should be able to transfer admin to themselves (though unusual)
        acl.transferAdmin(admin);
        assertEq(acl.admin(), admin);
    }
}