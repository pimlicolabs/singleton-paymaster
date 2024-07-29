// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {Test, console} from "forge-std/Test.sol";
import {MessageHashUtils} from "openzeppelin-contracts-v5.0.0/contracts/utils/cryptography/MessageHashUtils.sol";
import {PackedUserOperation} from "account-abstraction-v7/interfaces/PackedUserOperation.sol";
import {IStakeManager} from "account-abstraction-v7/interfaces/IStakeManager.sol";
import {IEntryPoint} from "account-abstraction-v7/interfaces/IEntryPoint.sol";

import {EntryPoint} from "./utils/account-abstraction/v07/core/EntryPoint.sol";
import {SimpleAccountFactory, SimpleAccount} from "./utils/account-abstraction/v07/samples/SimpleAccountFactory.sol";
import {SingletonPaymasterV7} from "../src/SingletonPaymasterV7.sol";
import {BasePaymaster} from "../src/base/BasePaymaster.sol";
import {PostOpMode} from "../src/interfaces/PostOpMode.sol";

import {TestERC20} from "./utils/TestERC20.sol";
import {TestCounter} from "./utils/TestCounter.sol";

contract BasePaymasterTest is Test {
    uint256 immutable INITIAL_PAYMASTER_DEPOSIT = 100e18;

    address payable beneficiary;
    address paymasterOwner;
    uint256 paymasterOwnerKey;
    address user;
    uint256 userKey;

    BasePaymaster paymaster;
    SimpleAccountFactory accountFactory;
    SimpleAccount account;
    EntryPoint entryPoint;

    function setUp() external {
        beneficiary = payable(makeAddr("beneficiary"));
        (paymasterOwner, paymasterOwnerKey) = makeAddrAndKey("paymasterOwner");
        (user, userKey) = makeAddrAndKey("user");

        entryPoint = new EntryPoint();
        accountFactory = new SimpleAccountFactory(entryPoint);
        account = accountFactory.createAccount(user, 0);
        paymaster = new SingletonPaymasterV7(address(entryPoint), paymasterOwner);

        vm.deal(paymasterOwner, 100e18);
        paymaster.deposit{value: INITIAL_PAYMASTER_DEPOSIT}();
    }

    function testConstructorSuccess() external {
        new SingletonPaymasterV7(address(0), address(1));
    }

    function testGetDeposit() external view {
        IStakeManager.DepositInfo memory info = IStakeManager(entryPoint).getDepositInfo(address(paymaster));
        vm.assertEq(paymaster.getDeposit(), info.deposit, "paymaster must deposit to EntryPoint during foundry setUp");
    }

    function testWithdrawTo() external {
        vm.prank(paymasterOwner);
        BasePaymaster(paymaster).withdrawTo(payable(user), INITIAL_PAYMASTER_DEPOSIT);
        IStakeManager.DepositInfo memory info = IStakeManager(entryPoint).getDepositInfo(address(paymaster));
        vm.assertEq(info.deposit, 0, "Paymaster balance should be zero after withdrawal from EntryPoint");
        vm.assertEq(
            user.balance, INITIAL_PAYMASTER_DEPOSIT, "User balance should equal initial deposit amount after withdrawal"
        );
    }

    function testAddStake() external {
        uint256 STAKE_AMOUNT = 1e18;
        vm.prank(paymasterOwner);
        BasePaymaster(paymaster).addStake{value: STAKE_AMOUNT}(10);
        IStakeManager.DepositInfo memory info = IStakeManager(entryPoint).getDepositInfo(address(paymaster));
        vm.assertTrue(info.staked, "Paymaster should be staked");
        vm.assertEq(info.stake, STAKE_AMOUNT, "Paymaster's should stake the correct amount");
    }

    function testUnlockWithdrawStake() external {
        uint256 STAKE_AMOUNT = 1e18;
        uint32 UNSTAKE_DELAY = 10;
        vm.startPrank(paymasterOwner);
        BasePaymaster(paymaster).addStake{value: STAKE_AMOUNT}(UNSTAKE_DELAY);
        BasePaymaster(paymaster).unlockStake();
        vm.warp(block.timestamp + UNSTAKE_DELAY);
        BasePaymaster(paymaster).withdrawStake(payable(user));

        IStakeManager.DepositInfo memory info = IStakeManager(entryPoint).getDepositInfo(address(paymaster));
        vm.assertFalse(info.staked, "Paymaster should not be staked");
        vm.assertEq(info.stake, 0, "Paymaster's stake should be empty");
        vm.assertEq(user.balance, STAKE_AMOUNT, "Stake recipient should have received full stake");
    }

    function testOwnershipTransfer() external {
        vm.startPrank(paymasterOwner);
        assertEq(paymaster.owner(), paymasterOwner);
        paymaster.transferOwnership(beneficiary);
        assertEq(paymaster.owner(), beneficiary);
        vm.stopPrank();
    }
}
