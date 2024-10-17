// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Test, console} from "forge-std/Test.sol";

import {MagicSpendPlusMinusHalf, WithdrawRequest, WithdrawRequestSignatures, CallStruct} from "../src/MagicSpendPlusMinusHalf.sol";
import {TestERC20} from "./utils/TestERC20.sol";
import {ForceReverter} from "./utils/ForceReverter.sol";

import {MessageHashUtils} from "openzeppelin-contracts-v5.0.2/contracts/utils/cryptography/MessageHashUtils.sol";
import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";


contract MagicSpendPlusMinusHalfTest is Test {
    address immutable OWNER = makeAddr("owner");
    address immutable RECIPIENT = makeAddr("recipient");

    error FailedToAddStake(bytes reason);

    address signer;
    uint256 signerKey;

    address alice;
    uint256 aliceKey;

    address bob;
    uint256 bobKey;

    ForceReverter forceReverter;
    MagicSpendPlusMinusHalf magicSpendPlusMinusHalf;
    TestERC20 token;

    function setUp() external {
        (signer, signerKey) = makeAddrAndKey("signer");
        (alice, aliceKey) = makeAddrAndKey("alice");
        (bob, bobKey) = makeAddrAndKey("bob");

        magicSpendPlusMinusHalf = new MagicSpendPlusMinusHalf(OWNER, new address[](0));
        token = new TestERC20(18);
        forceReverter = new ForceReverter();

        vm.prank(OWNER);
        magicSpendPlusMinusHalf.addSigner(signer);

        vm.deal(alice, 100 ether);
        token.sudoMint(alice, 100 ether);

        vm.prank(alice);
        token.approve(address(magicSpendPlusMinusHalf), 100 ether);
    }

    function testWithdrawNativeTokenSuccess() external {
        uint128 amount = 5 ether;
        address asset = address(0);
        uint256 nonce = 0;

        _addStake(asset, amount);

        WithdrawRequest memory withdrawRequest = WithdrawRequest({
            chainId: block.chainid,
            amount: amount,
            asset: asset,
            nonce: nonce,
            recipient: RECIPIENT,
            preCalls: new CallStruct[](0),
            postCalls: new CallStruct[](0),
            validUntil: 0,
            validAfter: 0
        });

        vm.expectEmit(address(magicSpendPlusMinusHalf));
        emit MagicSpendPlusMinusHalf.WithdrawRequestFulfilled(
            magicSpendPlusMinusHalf.getHash(withdrawRequest),
            alice,
            asset,
            amount,
            RECIPIENT,
            nonce
        );

        vm.prank(RECIPIENT);

        WithdrawRequestSignatures memory signatures = WithdrawRequestSignatures({
            requesterSignature: signWithdrawRequest(withdrawRequest, bobKey),
            accountSignature: signWithdrawRequest(withdrawRequest, aliceKey),
            magicSpendOperatorSignature: signWithdrawRequest(withdrawRequest, signerKey)
        });

        magicSpendPlusMinusHalf.claim(
            withdrawRequest,
            signatures
        );
        vm.assertEq(RECIPIENT.balance, 5 ether, "Withdrawn funds should go to recipient");
    }

    function testWithdrawERC20TokenSuccess() external {
        uint128 amount = 5 ether;
        address asset = address(token);
        uint256 nonce = 0;

        _addStake(asset, amount);

        WithdrawRequest memory withdrawRequest = WithdrawRequest({
            chainId: block.chainid,
            amount: amount,
            asset: asset,
            nonce: nonce,
            recipient: RECIPIENT,
            preCalls: new CallStruct[](0),
            postCalls: new CallStruct[](0),
            validUntil: 0,
            validAfter: 0
        });

        vm.expectEmit(address(magicSpendPlusMinusHalf));
        emit MagicSpendPlusMinusHalf.WithdrawRequestFulfilled(
            magicSpendPlusMinusHalf.getHash(withdrawRequest),
            alice,
            asset,
            amount,
            RECIPIENT,
            nonce
        );

        vm.prank(RECIPIENT);

        WithdrawRequestSignatures memory signatures = WithdrawRequestSignatures({
            requesterSignature: signWithdrawRequest(withdrawRequest, bobKey),
            accountSignature: signWithdrawRequest(withdrawRequest, aliceKey),
            magicSpendOperatorSignature: signWithdrawRequest(withdrawRequest, signerKey)
        });

        magicSpendPlusMinusHalf.claim(withdrawRequest, signatures);
        vm.assertEq(token.balanceOf(RECIPIENT), 5 ether, "Withdrawn funds should go to recipient");
    }

    function test_RevertWhen_ValidUntilInvalid() external {
        uint128 amount = 5 ether;
        address asset = address(0);
        uint256 nonce = 0;
        uint48 testValidUntil = uint48(block.timestamp + 5);

        vm.warp(500);

        _addStake(asset, amount);

        WithdrawRequest memory withdrawRequest = WithdrawRequest({
            chainId: block.chainid,
            amount: amount,
            asset: asset,
            nonce: nonce,
            recipient: RECIPIENT,
            validUntil: testValidUntil,
            preCalls: new CallStruct[](0),
            postCalls: new CallStruct[](0),
            validAfter: 0
        });

        WithdrawRequestSignatures memory signatures = WithdrawRequestSignatures({
            requesterSignature: signWithdrawRequest(withdrawRequest, bobKey),
            accountSignature: signWithdrawRequest(withdrawRequest, aliceKey),
            magicSpendOperatorSignature: signWithdrawRequest(withdrawRequest, signerKey)
        });

        // should throw if withdraw request was sent pass expiry.
        vm.expectRevert(abi.encodeWithSelector(MagicSpendPlusMinusHalf.RequestExpired.selector));
        magicSpendPlusMinusHalf.claim(withdrawRequest, signatures);
    }

    function test_RevertWhen_ValidAfterInvalid() external {
        uint128 amount = 5 ether;
        address asset = address(0);
        uint256 nonce = 0;
        uint48 testValidAfter = 4096;

        vm.warp(500);

        _addStake(asset, amount);

        WithdrawRequest memory withdrawRequest = WithdrawRequest({
            chainId: block.chainid,
            amount: amount,
            asset: asset,
            nonce: nonce,
            recipient: RECIPIENT,
            validAfter: testValidAfter,
            preCalls: new CallStruct[](0),
            postCalls: new CallStruct[](0),
            validUntil: 0
        });

        WithdrawRequestSignatures memory signatures = WithdrawRequestSignatures({
            requesterSignature: signWithdrawRequest(withdrawRequest, bobKey),
            accountSignature: signWithdrawRequest(withdrawRequest, aliceKey),
            magicSpendOperatorSignature: signWithdrawRequest(withdrawRequest, signerKey)
        });

        // should throw if withdraw request was sent too early.
        vm.expectRevert(abi.encodeWithSelector(MagicSpendPlusMinusHalf.RequestNotYetValid.selector));
        magicSpendPlusMinusHalf.claim(withdrawRequest, signatures);
    }


    function test_RevertWhen_AccountSignatureInvalid() external {
        uint128 amount = 5 ether;
        address asset = address(0);
        uint256 nonce = 0;
        (, uint256 unauthorizedSingerKey) = makeAddrAndKey("unauthorizedSinger");

        _addStake(asset, amount);

        WithdrawRequest memory withdrawRequest = WithdrawRequest({
            chainId: block.chainid,
            amount: amount,
            asset: asset,
            nonce: nonce,
            recipient: RECIPIENT,
            preCalls: new CallStruct[](0),
            postCalls: new CallStruct[](0),
            validUntil: 0,
            validAfter: 0
        });

        WithdrawRequestSignatures memory signatures = WithdrawRequestSignatures({
            requesterSignature: signWithdrawRequest(withdrawRequest, bobKey),
            accountSignature: signWithdrawRequest(withdrawRequest, unauthorizedSingerKey),
            magicSpendOperatorSignature: signWithdrawRequest(withdrawRequest, signerKey)
        });

        vm.expectRevert(abi.encodeWithSelector(SafeTransferLib.ETHTransferFailed.selector));
        magicSpendPlusMinusHalf.claim(withdrawRequest, signatures);
    }

    function test_RevertWhen_SignerSignatureInvalid() external {
        uint128 amount = 5 ether;
        address asset = address(0);
        uint256 nonce = 0;
        (, uint256 unauthorizedSingerKey) = makeAddrAndKey("unauthorizedSinger");

        _addStake(asset, amount);

        WithdrawRequest memory withdrawRequest = WithdrawRequest({
            chainId: block.chainid,
            amount: amount,
            asset: asset,
            nonce: nonce,
            recipient: RECIPIENT,
            preCalls: new CallStruct[](0),
            postCalls: new CallStruct[](0),
            validUntil: 0,
            validAfter: 0
        });

        WithdrawRequestSignatures memory signatures = WithdrawRequestSignatures({
            requesterSignature: signWithdrawRequest(withdrawRequest, bobKey),
            accountSignature: signWithdrawRequest(withdrawRequest, aliceKey),
            magicSpendOperatorSignature: signWithdrawRequest(withdrawRequest, unauthorizedSingerKey)
        });

        vm.expectRevert(abi.encodeWithSelector(MagicSpendPlusMinusHalf.SignatureInvalid.selector));
        magicSpendPlusMinusHalf.claim(withdrawRequest, signatures);
    }

    function test_RevertWhen_NonceInvalid() external {
        uint128 amount = 5 ether;
        address asset = address(0);
        uint256 nonce = 0;

        _addStake(asset, amount);

        WithdrawRequest memory withdrawRequest = WithdrawRequest({
            chainId: block.chainid,
            amount: amount,
            asset: asset,
            nonce: nonce,
            recipient: RECIPIENT,
            preCalls: new CallStruct[](0),
            postCalls: new CallStruct[](0),
            validUntil: 0,
            validAfter: 0
        });

        WithdrawRequestSignatures memory signatures = WithdrawRequestSignatures({
            requesterSignature: signWithdrawRequest(withdrawRequest, bobKey),
            accountSignature: signWithdrawRequest(withdrawRequest, aliceKey),
            magicSpendOperatorSignature: signWithdrawRequest(withdrawRequest, signerKey)
        });

        // force burn nonce
        vm.expectEmit(address(magicSpendPlusMinusHalf));

        emit MagicSpendPlusMinusHalf.WithdrawRequestFulfilled(
            magicSpendPlusMinusHalf.getHash(withdrawRequest),
            alice,
            asset,
            amount,
            RECIPIENT,
            nonce
        );

        magicSpendPlusMinusHalf.claim(withdrawRequest, signatures);

        // double spending should throw nonce error
        vm.expectRevert(abi.encodeWithSelector(MagicSpendPlusMinusHalf.NonceInvalid.selector, nonce));
        magicSpendPlusMinusHalf.claim(withdrawRequest, signatures);
    }

    function test_RevertWhen_WithdrawRequestTransferFailed() external {
        uint128 amount = 5 ether;
        address asset = address(0);
        uint256 nonce = 0;

        WithdrawRequest memory withdrawRequest = WithdrawRequest({
            chainId: block.chainid,
            amount: amount,
            asset: asset,
            nonce: nonce,
            recipient: RECIPIENT,
            preCalls: new CallStruct[](0),
            postCalls: new CallStruct[](0),
            validUntil: 0,
            validAfter: 0
        });

        WithdrawRequestSignatures memory signatures = WithdrawRequestSignatures({
            requesterSignature: signWithdrawRequest(withdrawRequest, bobKey),
            accountSignature: signWithdrawRequest(withdrawRequest, aliceKey),
            magicSpendOperatorSignature: signWithdrawRequest(withdrawRequest, signerKey)
        });

        // should throw when ETH withdraw request could not be fulfilled due to insufficient funds.
        vm.expectRevert(abi.encodeWithSelector(SafeTransferLib.ETHTransferFailed.selector));
        magicSpendPlusMinusHalf.claim(withdrawRequest, signatures);

        // should throw when ERC20 withdraw request could not be fulfilled due to insufficient funds.
        withdrawRequest.asset = address(token);

        signatures.requesterSignature = signWithdrawRequest(withdrawRequest, bobKey);
        signatures.accountSignature = signWithdrawRequest(withdrawRequest, aliceKey);
        signatures.magicSpendOperatorSignature = signWithdrawRequest(withdrawRequest, signerKey);

        vm.expectRevert(abi.encodeWithSelector(SafeTransferLib.TransferFailed.selector));
        magicSpendPlusMinusHalf.claim(withdrawRequest, signatures);
    }

    function test_RevertWhen_PreCallReverts() external {
        uint128 amount = 5 ether;
        address asset = address(0);
        uint256 nonce = 0;

        string memory revertMessage = "MAGIC";

        _addStake(asset, amount);

        WithdrawRequest memory withdrawRequest = WithdrawRequest({
            chainId: block.chainid,
            amount: amount,
            asset: asset,
            nonce: nonce,
            recipient: RECIPIENT,
            preCalls: new CallStruct[](1),
            postCalls: new CallStruct[](0),
            validUntil: 0,
            validAfter: 0
        });
        // force a revert by calling non existant function
        withdrawRequest.preCalls[0] = CallStruct({
            to: address(forceReverter),
            data: abi.encodeWithSignature("forceRevertWithMessage(string)", revertMessage),
            value: 0
        });

        WithdrawRequestSignatures memory signatures = WithdrawRequestSignatures({
            requesterSignature: signWithdrawRequest(withdrawRequest, bobKey),
            accountSignature: signWithdrawRequest(withdrawRequest, aliceKey),
            magicSpendOperatorSignature: signWithdrawRequest(withdrawRequest, signerKey)
        });

        bytes memory revertBytes = abi.encodeWithSelector(ForceReverter.RevertWithMsg.selector, revertMessage);
        vm.expectRevert(abi.encodeWithSelector(MagicSpendPlusMinusHalf.PreCallReverted.selector, revertBytes));
        magicSpendPlusMinusHalf.claim(withdrawRequest, signatures);
    }

    function test_RevertWhen_PostCallReverts() external {
        uint128 amount = 5 ether;
        address asset = address(0);
        uint256 nonce = 0;

        _addStake(asset, amount);

        string memory revertMessage = "MAGIC";

        WithdrawRequest memory withdrawRequest = WithdrawRequest({
            chainId: block.chainid,
            amount: amount,
            asset: asset,
            nonce: nonce,
            recipient: RECIPIENT,
            preCalls: new CallStruct[](0),
            postCalls: new CallStruct[](1),
            validUntil: 0,
            validAfter: 0
        });
        // force a revert by calling non existant function
        withdrawRequest.postCalls[0] = CallStruct({
            to: address(forceReverter),
            data: abi.encodeWithSignature("forceRevertWithMessage(string)", revertMessage),
            value: 0
        });

        WithdrawRequestSignatures memory signatures = WithdrawRequestSignatures({
            requesterSignature: signWithdrawRequest(withdrawRequest, bobKey),
            accountSignature: signWithdrawRequest(withdrawRequest, aliceKey),
            magicSpendOperatorSignature: signWithdrawRequest(withdrawRequest, signerKey)
        });

        vm.deal(address(magicSpendPlusMinusHalf), 100 ether);
        vm.prank(RECIPIENT);
        bytes memory revertBytes = abi.encodeWithSelector(ForceReverter.RevertWithMsg.selector, revertMessage);
        vm.expectRevert(abi.encodeWithSelector(MagicSpendPlusMinusHalf.PostCallReverted.selector, revertBytes));
        magicSpendPlusMinusHalf.claim(withdrawRequest, signatures);
    }

    // // = = = Helpers = = =

    function signWithdrawRequest(WithdrawRequest memory withdrawRequest, uint256 signingKey)
        internal
        view
        returns (bytes memory signature)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signingKey, magicSpendPlusMinusHalf.getHash(withdrawRequest));
        return abi.encodePacked(r, s, v);
    }

    function _addStake(
        address asset,
        uint128 amount
    ) internal {
        vm.prank(alice);

        if (asset == address(0)) {
            (bool success, bytes memory result) = address(magicSpendPlusMinusHalf).call{value: amount}("");

            if (!success) {
                revert FailedToAddStake(result);
            }
        } else {
            magicSpendPlusMinusHalf.addStake(asset, amount, 60);
        }

        vm.stopPrank();
    }
}
