// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Test, console} from "forge-std/Test.sol";

import {MessageHashUtils} from "openzeppelin-contracts-v5.0.2/contracts/utils/cryptography/MessageHashUtils.sol";
import {Ownable} from "openzeppelin-contracts-v5.0.2/contracts/access/Ownable.sol";

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
    uint256 immutable INITIAL_PAYMASTER_DEPOSIT = 100 ether;

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
        vm.assertEq(
            paymaster.getDeposit(), info.deposit, "Paymaster's getDeposit function must match deposit on EntryPoint"
        );
        vm.assertEq(
            paymaster.getDeposit(),
            INITIAL_PAYMASTER_DEPOSIT,
            "paymaster must deposit `INITIAL_PAYMASTER_DEPOSIT` to EntryPoint during setUp"
        );
    }

    function testWithdrawTo() external {
        // only owner should be able to withdraw.
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        BasePaymaster(paymaster).withdrawTo(payable(user), INITIAL_PAYMASTER_DEPOSIT);

        // should pass if caller is owner.
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
        uint32 UNSTAKE_DELAY = 10;

        // only owner should be able to add stake.
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        BasePaymaster(paymaster).addStake{value: STAKE_AMOUNT}(UNSTAKE_DELAY);

        // should pass if caller is owner.
        vm.prank(paymasterOwner);
        BasePaymaster(paymaster).addStake{value: STAKE_AMOUNT}(UNSTAKE_DELAY);
        IStakeManager.DepositInfo memory info = IStakeManager(entryPoint).getDepositInfo(address(paymaster));
        vm.assertTrue(info.staked, "Paymaster should be staked");
        vm.assertEq(info.stake, STAKE_AMOUNT, "Paymaster should have staked the correct amount");
        vm.assertEq(info.unstakeDelaySec, UNSTAKE_DELAY, "Paymaster should have correct unstake delay");

        // should be able to add to existing stake.
        vm.prank(paymasterOwner);
        BasePaymaster(paymaster).addStake{value: STAKE_AMOUNT}(UNSTAKE_DELAY);
        info = IStakeManager(entryPoint).getDepositInfo(address(paymaster));
        vm.assertTrue(info.staked, "Paymaster should be staked");
        vm.assertEq(info.stake, STAKE_AMOUNT * 2, "Paymaster should be able to add to existing stake");
        vm.assertEq(info.unstakeDelaySec, UNSTAKE_DELAY, "Paymaster should have correct unstake delay");
    }

    function testUnlockWithdrawStake() external {
        uint256 STAKE_AMOUNT = 1e18;
        uint32 UNSTAKE_DELAY = 10;

        // add stake so that we can test unstaking.
        vm.prank(paymasterOwner);
        BasePaymaster(paymaster).addStake{value: STAKE_AMOUNT}(UNSTAKE_DELAY);

        // only owner should be able to unlockStatke + unstake.
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        BasePaymaster(paymaster).unlockStake();
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        BasePaymaster(paymaster).withdrawStake(payable(user));

        // should pass if caller is owner.
        vm.startPrank(paymasterOwner);
        BasePaymaster(paymaster).unlockStake();
        vm.warp(block.timestamp + UNSTAKE_DELAY);
        BasePaymaster(paymaster).withdrawStake(payable(user));

        IStakeManager.DepositInfo memory info = IStakeManager(entryPoint).getDepositInfo(address(paymaster));
        vm.assertFalse(info.staked, "Paymaster should not be staked");
        vm.assertEq(info.stake, 0, "Paymaster's stake should be empty");
        vm.assertEq(user.balance, STAKE_AMOUNT, "Stake recipient should have received full stake");
    }

    function testOwnershipTransfer() external {
        // only owner should be able to transfer ownership.
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        paymaster.transferOwnership(beneficiary);

        // should pass if caller is owner.
        vm.startPrank(paymasterOwner);
        assertEq(paymaster.owner(), paymasterOwner);
        paymaster.transferOwnership(beneficiary);
        assertEq(paymaster.owner(), beneficiary);
        vm.stopPrank();
    }
}
