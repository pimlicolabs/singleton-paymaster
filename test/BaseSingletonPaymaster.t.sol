// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Test, console} from "forge-std/Test.sol";
import {MessageHashUtils} from "openzeppelin-contracts-v5.0.0/contracts/utils/cryptography/MessageHashUtils.sol";
import {PackedUserOperation} from "account-abstraction-v7/interfaces/PackedUserOperation.sol";

import {EntryPoint} from "./utils/account-abstraction/v07/core/EntryPoint.sol";
import {SimpleAccountFactory, SimpleAccount} from "./utils/account-abstraction/v07/samples/SimpleAccountFactory.sol";
import {SingletonPaymasterV7} from "../src/SingletonPaymasterV7.sol";

import {TestERC20} from "./utils/TestERC20.sol";
import {TestCounter} from "./utils/TestCounter.sol";

contract SingletonPaymasterTest is Test {
    address payable beneficiary;
    address paymasterOwner;
    uint256 paymasterOwnerKey;
    address user;
    uint256 userKey;

    SingletonPaymasterV7 paymaster;
    SimpleAccountFactory accountFactory;
    SimpleAccount account;
    EntryPoint entryPoint;

    TestERC20 token;
    TestCounter counter;

    function setUp() external {
        token = new TestERC20(18);
        counter = new TestCounter();

        beneficiary = payable(makeAddr("beneficiary"));
        (paymasterOwner, paymasterOwnerKey) = makeAddrAndKey("paymasterOwner");
        (user, userKey) = makeAddrAndKey("user");

        entryPoint = new EntryPoint();
        accountFactory = new SimpleAccountFactory(entryPoint);
        account = accountFactory.createAccount(user, 0);
        paymaster = new SingletonPaymasterV7(address(entryPoint), paymasterOwner);
        paymaster.deposit{value: 100e18}();
    }

    function testDeploy() external view {
        assertEq(address(paymaster.entryPoint()), address(entryPoint));
        assertEq(address(paymaster.owner()), paymasterOwner);
        assertEq(address(paymaster.treasury()), paymasterOwner);
    }

    function testUpdateTreasury() external {
        vm.startPrank(paymasterOwner);
        assertEq(paymaster.treasury(), paymasterOwner);
        paymaster.setTreasury(beneficiary);
        assertEq(paymaster.treasury(), beneficiary);
        vm.stopPrank();
    }

    function testAddSigner() external {
        vm.startPrank(paymasterOwner);
        assertFalse(paymaster.signers(beneficiary));
        paymaster.addSigner(beneficiary);
        assertTrue(paymaster.signers(beneficiary));
        vm.stopPrank();
    }

    function testRemoveSigner() external {
        vm.startPrank(paymasterOwner);

        paymaster.addSigner(paymasterOwner);
        assertTrue(paymaster.signers(paymasterOwner));

        paymaster.removeSigner(paymasterOwner);
        assertFalse(paymaster.signers(paymasterOwner));
    }
}
