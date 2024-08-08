// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Test, console} from "forge-std/Test.sol";
import {MessageHashUtils} from "openzeppelin-contracts-v5.0.0/contracts/utils/cryptography/MessageHashUtils.sol";
import {PackedUserOperation} from "account-abstraction-v7/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "@account-abstraction-v7/interfaces/IEntryPoint.sol";

import {EntryPoint} from "./utils/account-abstraction/v07/core/EntryPoint.sol";
import {SimpleAccountFactory, SimpleAccount} from "./utils/account-abstraction/v07/samples/SimpleAccountFactory.sol";
import {SingletonPaymasterV7} from "../src/SingletonPaymasterV7.sol";
import {WithdrawRequest, BaseSingletonPaymaster} from "../src/base/BaseSingletonPaymaster.sol";
import {BasePaymaster} from "../src/base/BasePaymaster.sol";

import {TestERC20} from "./utils/TestERC20.sol";
import {TestCounter} from "./utils/TestCounter.sol";

contract BaseSingletonPaymasterTest is Test {
    address payable beneficiary;
    address paymasterOwner;
    uint256 paymasterOwnerKey;
    address paymasterSigner;
    uint256 paymasterSignerKey;
    address user;
    uint256 userKey;

    uint256 constant INITIAL_DEPOSIT = 100 ether;
    BaseSingletonPaymaster paymaster;
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
        (paymasterSigner, paymasterSignerKey) = makeAddrAndKey("paymasterSigner");
        (user, userKey) = makeAddrAndKey("user");

        entryPoint = new EntryPoint();
        accountFactory = new SimpleAccountFactory(entryPoint);
        account = accountFactory.createAccount(user, 0);
        paymaster = new SingletonPaymasterV7(address(entryPoint), paymasterOwner);
        paymaster.deposit{value: INITIAL_DEPOSIT}();

        vm.prank(paymasterOwner);
        paymaster.addSigner(paymasterSigner);
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

    function testWithdrawSuccess() public {
        address alice = payable(makeAddr("alice"));
        uint256 withdrawAmt = 1 ether;

        WithdrawRequest memory request = WithdrawRequest({
            recipient: address(alice),
            nonce: 0,
            amount: withdrawAmt,
            expiry: uint48(block.timestamp + 60_000),
            signature: "0x"
        });
        request.signature = signWithdrawRequest(request);

        paymaster.requestWithdraw(request);
        assertEq(alice.balance, withdrawAmt);
    }

    function testWithdraw_RevertWhen_WithdrawTooLarge() external {
        address alice = payable(makeAddr("alice"));
        uint256 invalidWithdrawAmt = 1000 ether;
        uint48 expiry = uint48(block.timestamp + 60_000);

        // set paymasterMinBalance
        vm.prank(paymasterOwner);
        uint256 paymasterMinBalance = 1 ether;
        paymaster.setPaymasterMinBalance(paymasterMinBalance);

        // send withdrawRequest
        WithdrawRequest memory request =
            WithdrawRequest({recipient: alice, nonce: 0, amount: invalidWithdrawAmt, expiry: expiry, signature: "0x"});
        request.signature = signWithdrawRequest(request);

        uint256 maxAllowedWithdraw = BasePaymaster(paymaster).getDeposit() - paymaster.paymasterMinBalance();
        vm.expectRevert(
            abi.encodeWithSelector(
                BaseSingletonPaymaster.WithdrawTooLarge.selector, invalidWithdrawAmt, maxAllowedWithdraw
            )
        );
        paymaster.requestWithdraw(request);
    }

    function testWithdraw_RevertWhen_NonceInvalid() external {
        address alice = payable(makeAddr("alice"));
        uint256 withdrawAmt = 1 ether;
        uint48 expiry = uint48(block.timestamp + 60_000);

        // send succesful request to burn nonce
        WithdrawRequest memory request =
            WithdrawRequest({recipient: alice, nonce: 0, amount: withdrawAmt, expiry: expiry, signature: "0x"});
        request.signature = signWithdrawRequest(request);

        paymaster.requestWithdraw(request);
        assertEq(alice.balance, withdrawAmt);

        // try again with the same burnt nonce
        WithdrawRequest memory invalidRequest = WithdrawRequest({
            recipient: alice,
            nonce: 0, // try again with same nonce (expect a revert)
            amount: 0.45 ether,
            expiry: expiry,
            signature: "0x"
        });
        invalidRequest.signature = signWithdrawRequest(invalidRequest);

        vm.expectRevert(abi.encodeWithSelector(BaseSingletonPaymaster.WithdrawNonceInvalid.selector, 0));
        paymaster.requestWithdraw(invalidRequest);
    }

    function testWithdraw_RevertWhen_SignatureInvalid() external {
        uint256 withdrawAmt = 1 ether;

        WithdrawRequest memory request = WithdrawRequest({
            recipient: address(0),
            nonce: 0,
            amount: withdrawAmt,
            expiry: uint48(block.timestamp + 5_000),
            signature: "0x"
        });

        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(paymaster.getWithdrawHash(request));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(uint256(42), digest);
        request.signature = abi.encodePacked(r, s, v);

        vm.expectRevert(abi.encodeWithSelector(BaseSingletonPaymaster.WithdrawSignatureInvalid.selector));
        paymaster.requestWithdraw(request);
    }

    function testWithdraw_RevertWhen_Expired() external {
        address alice = payable(makeAddr("alice"));
        uint256 withdrawAmt = 1 ether;

        vm.warp(100_000);

        WithdrawRequest memory request = WithdrawRequest({
            recipient: address(alice),
            nonce: 0,
            amount: withdrawAmt,
            expiry: uint48(block.timestamp - 5_000),
            signature: "0x"
        });
        request.signature = signWithdrawRequest(request);

        vm.expectRevert(abi.encodeWithSelector(BaseSingletonPaymaster.WithdrawRequestExpired.selector));
        paymaster.requestWithdraw(request);
    }

    function signWithdrawRequest(WithdrawRequest memory request) internal view returns (bytes memory) {
        bytes32 hash = paymaster.getWithdrawHash(request);

        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(hash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(paymasterSignerKey, digest);
        return abi.encodePacked(r, s, v);
    }
}
