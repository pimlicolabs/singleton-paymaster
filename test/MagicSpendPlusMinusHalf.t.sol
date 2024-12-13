// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { Test, console } from "forge-std/Test.sol";

import { MagicSpendPlusMinusHalf, WithdrawRequest, CallStruct } from "../src/MagicSpendPlusMinusHalf.sol";
import { TestERC20 } from "./utils/TestERC20.sol";
import { ForceReverter } from "./utils/ForceReverter.sol";

import { MessageHashUtils } from "openzeppelin-contracts-v5.0.2/contracts/utils/cryptography/MessageHashUtils.sol";
import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";

contract MagicSpendPlusMinusHalfTest is Test {
    address immutable OWNER = makeAddr("owner");
    address immutable RECIPIENT = makeAddr("recipient");

    address signer;
    uint256 signerKey;

    ForceReverter forceReverter;
    MagicSpendPlusMinusHalf magicSpendPlusMinusHalf;
    TestERC20 token;

    function setUp() external {
        (signer, signerKey) = makeAddrAndKey("signer");

        magicSpendPlusMinusHalf = new MagicSpendPlusMinusHalf(OWNER, new address[](0));
        token = new TestERC20(18);
        forceReverter = new ForceReverter();

        vm.prank(OWNER);
        magicSpendPlusMinusHalf.addSigner(signer);
    }

    function testWithdrawNativeTokenSuccess() external {
        uint256 amount = 5 ether;
        address asset = address(0);
        uint256 nonce = 0;

        WithdrawRequest memory withdrawRequest = WithdrawRequest({
            amount: amount,
            asset: asset,
            nonce: nonce,
            preCalls: new CallStruct[](0),
            postCalls: new CallStruct[](0),
            validUntil: 0,
            validAfter: 0,
            signature: ""
        });
        withdrawRequest.signature = signWithdrawRequest(withdrawRequest, signerKey);

        vm.deal(address(magicSpendPlusMinusHalf), amount);
        vm.expectEmit(address(magicSpendPlusMinusHalf));
        emit MagicSpendPlusMinusHalf.WithdrawRequestFulfilled(RECIPIENT, amount, asset, nonce);

        vm.prank(RECIPIENT);
        magicSpendPlusMinusHalf.requestWithdraw(withdrawRequest);
        vm.assertEq(RECIPIENT.balance, 5 ether, "Withdrawn funds should go to recipient");
    }

    function testWithdrawERC20TokenSuccess() external {
        uint256 amount = 5 ether;
        address asset = address(token);
        uint256 nonce = 0;

        WithdrawRequest memory withdrawRequest = WithdrawRequest({
            amount: amount,
            asset: asset,
            nonce: nonce,
            preCalls: new CallStruct[](0),
            postCalls: new CallStruct[](0),
            validUntil: 0,
            validAfter: 0,
            signature: ""
        });
        withdrawRequest.signature = signWithdrawRequest(withdrawRequest, signerKey);

        token.sudoMint(address(magicSpendPlusMinusHalf), 5 ether);

        vm.expectEmit(address(magicSpendPlusMinusHalf));
        emit MagicSpendPlusMinusHalf.WithdrawRequestFulfilled(RECIPIENT, amount, asset, nonce);

        vm.prank(RECIPIENT);
        magicSpendPlusMinusHalf.requestWithdraw(withdrawRequest);
        vm.assertEq(token.balanceOf(RECIPIENT), 5 ether, "Withdrawn funds should go to recipient");
    }

    function test_RevertWhen_TimestampInvalid() external {
        uint256 amount = 5 ether;
        address asset = address(0);
        uint256 nonce = 0;
        uint48 testValidUntil = uint48(block.timestamp + 5);
        uint48 testValidAfter = 4096;

        vm.warp(500);

        WithdrawRequest memory withdrawRequest = WithdrawRequest({
            amount: amount,
            asset: asset,
            nonce: nonce,
            validUntil: testValidUntil,
            preCalls: new CallStruct[](0),
            postCalls: new CallStruct[](0),
            validAfter: 0,
            signature: ""
        });
        withdrawRequest.signature = signWithdrawRequest(withdrawRequest, signerKey);

        // should throw if withdraw request was sent pass expiry.
        vm.prank(RECIPIENT);
        vm.expectRevert(abi.encodeWithSelector(MagicSpendPlusMinusHalf.RequestExpired.selector));
        magicSpendPlusMinusHalf.requestWithdraw(withdrawRequest);

        withdrawRequest = WithdrawRequest({
            amount: amount,
            asset: asset,
            nonce: nonce,
            validAfter: testValidAfter,
            preCalls: new CallStruct[](0),
            postCalls: new CallStruct[](0),
            validUntil: 0,
            signature: ""
        });
        withdrawRequest.signature = signWithdrawRequest(withdrawRequest, signerKey);

        // should throw if withdraw request was sent too early.
        vm.prank(RECIPIENT);
        vm.expectRevert(abi.encodeWithSelector(MagicSpendPlusMinusHalf.RequestNotYetValid.selector));
        magicSpendPlusMinusHalf.requestWithdraw(withdrawRequest);
    }

    function test_RevertWhen_SignatureInvalid() external {
        uint256 amount = 5 ether;
        address asset = address(0);
        uint256 nonce = 0;
        (, uint256 unauthorizedSingerKey) = makeAddrAndKey("unauthorizedSinger");

        WithdrawRequest memory withdrawRequest = WithdrawRequest({
            amount: amount,
            asset: asset,
            nonce: nonce,
            preCalls: new CallStruct[](0),
            postCalls: new CallStruct[](0),
            validUntil: 0,
            validAfter: 0,
            signature: ""
        });
        withdrawRequest.signature = signWithdrawRequest(withdrawRequest, unauthorizedSingerKey);

        vm.deal(address(magicSpendPlusMinusHalf), amount);

        vm.prank(RECIPIENT);
        vm.expectRevert(abi.encodeWithSelector(MagicSpendPlusMinusHalf.SignatureInvalid.selector));
        magicSpendPlusMinusHalf.requestWithdraw(withdrawRequest);
    }

    function test_RevertWhen_NonceInvalid() external {
        uint256 amount = 5 ether;
        address asset = address(0);
        uint256 nonce = 0;

        WithdrawRequest memory withdrawRequest = WithdrawRequest({
            amount: amount,
            asset: asset,
            nonce: nonce,
            preCalls: new CallStruct[](0),
            postCalls: new CallStruct[](0),
            validUntil: 0,
            validAfter: 0,
            signature: ""
        });
        withdrawRequest.signature = signWithdrawRequest(withdrawRequest, signerKey);

        // force burn nonce
        vm.deal(address(magicSpendPlusMinusHalf), amount);
        vm.expectEmit(address(magicSpendPlusMinusHalf));
        emit MagicSpendPlusMinusHalf.WithdrawRequestFulfilled(RECIPIENT, amount, asset, nonce);

        vm.prank(RECIPIENT);
        magicSpendPlusMinusHalf.requestWithdraw(withdrawRequest);

        // double spending should throw nonce error
        vm.expectRevert(abi.encodeWithSelector(MagicSpendPlusMinusHalf.NonceInvalid.selector, nonce));
        vm.prank(RECIPIENT);
        magicSpendPlusMinusHalf.requestWithdraw(withdrawRequest);
    }

    function test_RevertWhen_WithdrawRequestTransferFailed() external {
        uint256 amount = 5 ether;
        address asset = address(0);
        uint256 nonce = 0;

        WithdrawRequest memory withdrawRequest = WithdrawRequest({
            amount: amount,
            asset: asset,
            nonce: nonce,
            preCalls: new CallStruct[](0),
            postCalls: new CallStruct[](0),
            validUntil: 0,
            validAfter: 0,
            signature: ""
        });
        withdrawRequest.signature = signWithdrawRequest(withdrawRequest, signerKey);

        // should throw when ETH withdraw request could not be fulfilled due to insufficient funds.
        vm.prank(RECIPIENT);
        vm.expectRevert(abi.encodeWithSelector(SafeTransferLib.ETHTransferFailed.selector));
        magicSpendPlusMinusHalf.requestWithdraw(withdrawRequest);

        // should throw when ERC20 withdraw request could not be fulfilled due to insufficient funds.
        withdrawRequest.asset = address(token);
        withdrawRequest.signature = signWithdrawRequest(withdrawRequest, signerKey);
        vm.prank(RECIPIENT);
        vm.expectRevert(abi.encodeWithSelector(SafeTransferLib.TransferFailed.selector));
        magicSpendPlusMinusHalf.requestWithdraw(withdrawRequest);
    }

    function test_RevertWhen_PreCallReverts() external {
        uint256 amount = 5 ether;
        address asset = address(0);
        uint256 nonce = 0;

        string memory revertMessage = "MAGIC";

        WithdrawRequest memory withdrawRequest = WithdrawRequest({
            amount: amount,
            asset: asset,
            nonce: nonce,
            preCalls: new CallStruct[](1),
            postCalls: new CallStruct[](0),
            validUntil: 0,
            validAfter: 0,
            signature: ""
        });
        // force a revert by calling non existant function
        withdrawRequest.preCalls[0] = CallStruct({
            to: address(forceReverter),
            data: abi.encodeWithSignature("forceRevertWithMessage(string)", revertMessage),
            value: 0
        });
        withdrawRequest.signature = signWithdrawRequest(withdrawRequest, signerKey);

        vm.prank(RECIPIENT);
        bytes memory revertBytes = abi.encodeWithSelector(ForceReverter.RevertWithMsg.selector, revertMessage);
        vm.expectRevert(abi.encodeWithSelector(MagicSpendPlusMinusHalf.PreCallReverted.selector, revertBytes));
        magicSpendPlusMinusHalf.requestWithdraw(withdrawRequest);
    }

    function test_RevertWhen_PostCallReverts() external {
        uint256 amount = 5 ether;
        address asset = address(0);
        uint256 nonce = 0;

        string memory revertMessage = "MAGIC";

        WithdrawRequest memory withdrawRequest = WithdrawRequest({
            amount: amount,
            asset: asset,
            nonce: nonce,
            preCalls: new CallStruct[](0),
            postCalls: new CallStruct[](1),
            validUntil: 0,
            validAfter: 0,
            signature: ""
        });
        // force a revert by calling non existant function
        withdrawRequest.postCalls[0] = CallStruct({
            to: address(forceReverter),
            data: abi.encodeWithSignature("forceRevertWithMessage(string)", revertMessage),
            value: 0
        });
        withdrawRequest.signature = signWithdrawRequest(withdrawRequest, signerKey);

        vm.deal(address(magicSpendPlusMinusHalf), 100 ether);
        vm.prank(RECIPIENT);
        bytes memory revertBytes = abi.encodeWithSelector(ForceReverter.RevertWithMsg.selector, revertMessage);
        vm.expectRevert(abi.encodeWithSelector(MagicSpendPlusMinusHalf.PostCallReverted.selector, revertBytes));
        magicSpendPlusMinusHalf.requestWithdraw(withdrawRequest);
    }

    // = = = Helpers = = =

    function signWithdrawRequest(
        WithdrawRequest memory withdrawRequest,
        uint256 signingKey
    )
        internal
        view
        returns (bytes memory signature)
    {
        bytes32 hash = magicSpendPlusMinusHalf.getHash(RECIPIENT, withdrawRequest);
        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(hash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signingKey, digest);
        return abi.encodePacked(r, s, v);
    }
}
