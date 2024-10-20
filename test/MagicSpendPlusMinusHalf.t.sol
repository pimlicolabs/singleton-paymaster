// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Test, console} from "forge-std/Test.sol";

import {MagicSpendPlusMinusHalf, Request, RequestExecutionType, CallStruct} from "../src/MagicSpendPlusMinusHalf.sol";
import {LiquidityManager} from "./../src/base/LiquidityManager.sol";
import {TestERC20} from "./utils/TestERC20.sol";
import {ForceReverter} from "./utils/ForceReverter.sol";

import {MessageHashUtils} from "openzeppelin-contracts-v5.0.2/contracts/utils/cryptography/MessageHashUtils.sol";
import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";


contract MagicSpendPlusMinusHalfTest is Test {
    address immutable OWNER = makeAddr("owner");
    address immutable RECIPIENT = makeAddr("recipient");

    uint256 withdrawChainId = 111;
    uint256 claimChainId = 999;

    uint128 amount = 5 ether;
    uint128 fee = 0;

    error FailedToAddStake(bytes reason);

    address signer;
    uint256 signerKey;

    address alice;
    uint256 aliceKey;

    ForceReverter forceReverter;
    MagicSpendPlusMinusHalf magicSpendPlusMinusHalf;
    TestERC20 token;

    function setUp() external {
        (signer, signerKey) = makeAddrAndKey("signer");
        (alice, aliceKey) = makeAddrAndKey("alice");

        magicSpendPlusMinusHalf = new MagicSpendPlusMinusHalf(OWNER, signer);
        token = new TestERC20(18);
        forceReverter = new ForceReverter();

        vm.prank(OWNER);
        token.sudoMint(signer, 100 ether);
        token.sudoMint(alice, 100 ether);

        vm.deal(signer, 100 ether);
        vm.prank(signer);
        token.approve(address(magicSpendPlusMinusHalf), 100 ether);

        vm.prank(alice);
        vm.deal(alice, 100 ether);
        token.approve(address(magicSpendPlusMinusHalf), 100 ether);
    }

    function testWithdrawNativeTokenSuccess() external {
        _deposit(address(0), amount);
        _addStake(address(token), amount);

        address asset = address(0);

        Request memory request = Request({
            withdrawChainId: withdrawChainId,
            claimChainId: claimChainId,
            amount: amount,
            fee: fee,
            asset: asset,
            recipient: RECIPIENT,
            preCalls: new CallStruct[](0),
            postCalls: new CallStruct[](0),
            validUntil: 0,
            validAfter: 0,
            unstakeDelaySec: 0
        });

        vm.expectEmit(address(magicSpendPlusMinusHalf));
        emit MagicSpendPlusMinusHalf.RequestExecuted(
            RequestExecutionType.WITHDRAWN,
            magicSpendPlusMinusHalf.getHash(request)
        );

        vm.prank(RECIPIENT);
        vm.chainId(withdrawChainId);

        magicSpendPlusMinusHalf.withdraw(
            request,
            signWithdrawRequest(request, signerKey)
        );
        vm.assertEq(RECIPIENT.balance, 5 ether, "Withdrawn funds should go to recipient");
    }

    function testWithdrawERC20TokenSuccess() external {
        _deposit(address(token), amount);
        _addStake(address(token), amount);

        address asset = address(token);

        Request memory request = Request({
            withdrawChainId: withdrawChainId,
            claimChainId: claimChainId,
            amount: amount,
            fee: fee,
            asset: asset,
            recipient: RECIPIENT,
            preCalls: new CallStruct[](0),
            postCalls: new CallStruct[](0),
            validUntil: 0,
            validAfter: 0,
            unstakeDelaySec: 0
        });

        vm.chainId(withdrawChainId);
        vm.expectEmit(address(magicSpendPlusMinusHalf));
        emit MagicSpendPlusMinusHalf.RequestExecuted(
            RequestExecutionType.WITHDRAWN,
            magicSpendPlusMinusHalf.getHash(request)
        );

        magicSpendPlusMinusHalf.withdraw(
            request,
            signWithdrawRequest(request, signerKey)
        );
        vm.assertEq(token.balanceOf(RECIPIENT), 5 ether, "Withdrawn funds should go to recipient");
    }

    function test_RevertWhen_ValidUntilInvalid() external {
        _deposit(address(0), amount);
        _addStake(address(token), amount);

        address asset = address(0);
        uint48 testValidUntil = uint48(block.timestamp + 5);

        vm.warp(500);
        vm.chainId(withdrawChainId);

        Request memory request = Request({
            withdrawChainId: withdrawChainId,
            claimChainId: claimChainId,
            amount: amount,
            fee: fee,
            asset: asset,
            recipient: RECIPIENT,
            validUntil: testValidUntil,
            preCalls: new CallStruct[](0),
            postCalls: new CallStruct[](0),
            validAfter: 0,
            unstakeDelaySec: 0
        });

        bytes memory signature = signWithdrawRequest(request, signerKey);

        // should throw if withdraw request was sent pass expiry.
        vm.expectRevert(abi.encodeWithSelector(MagicSpendPlusMinusHalf.RequestExpired.selector));

        magicSpendPlusMinusHalf.withdraw(
            request,
            signature
        );
    }

    function test_RevertWhen_ValidAfterInvalid() external {
        _deposit(address(0), amount);
        _addStake(address(token), amount);

        address asset = address(0);
        uint48 testValidAfter = 4096;

        vm.warp(500);
        vm.chainId(withdrawChainId);

        Request memory request = Request({
            withdrawChainId: withdrawChainId,
            claimChainId: claimChainId,
            amount: amount,
            fee: fee,
            asset: asset,
            recipient: RECIPIENT,
            validAfter: testValidAfter,
            preCalls: new CallStruct[](0),
            postCalls: new CallStruct[](0),
            validUntil: 0,
            unstakeDelaySec: 0
        });

        bytes memory signature = signWithdrawRequest(request, signerKey);

        // should throw if withdraw request was sent too early.
        vm.expectRevert(abi.encodeWithSelector(MagicSpendPlusMinusHalf.RequestNotYetValid.selector));
        magicSpendPlusMinusHalf.withdraw(request, signature);
    }


    function test_RevertWhen_AccountSignatureInvalid() external {
        _deposit(address(0), amount);
        _addStake(address(token), amount);

        address asset = address(0);
        (, uint256 unauthorizedSingerKey) = makeAddrAndKey("unauthorizedSinger");

        vm.chainId(withdrawChainId);

        Request memory request = Request({
            withdrawChainId: withdrawChainId,
            claimChainId: claimChainId,
            amount: amount,
            fee: fee,
            asset: asset,
            recipient: RECIPIENT,
            preCalls: new CallStruct[](0),
            postCalls: new CallStruct[](0),
            validUntil: 0,
            validAfter: 0,
            unstakeDelaySec: 0
        });

        bytes memory signature = signWithdrawRequest(request, unauthorizedSingerKey);

        vm.expectRevert(abi.encodeWithSelector(MagicSpendPlusMinusHalf.SignatureInvalid.selector));
        magicSpendPlusMinusHalf.withdraw(request, signature);
    }

    function test_RevertWhen_RequestWithdrawnTwice() external {
        _deposit(address(0), amount);
        _addStake(address(token), amount);

        address asset = address(0);

        vm.chainId(withdrawChainId);

        Request memory request = Request({
            withdrawChainId: withdrawChainId,
            claimChainId: claimChainId,
            amount: amount,
            fee: fee,
            asset: asset,
            recipient: RECIPIENT,
            preCalls: new CallStruct[](0),
            postCalls: new CallStruct[](0),
            validUntil: 0,
            validAfter: 0,
            unstakeDelaySec: 0
        });

        bytes memory signature = signWithdrawRequest(request, signerKey);

        // force burn nonce
        vm.expectEmit(address(magicSpendPlusMinusHalf));

        emit MagicSpendPlusMinusHalf.RequestExecuted(
            RequestExecutionType.WITHDRAWN,
            magicSpendPlusMinusHalf.getHash(request)
        );

        magicSpendPlusMinusHalf.withdraw(request, signature);

        // double spending should throw nonce error
        vm.expectRevert(abi.encodeWithSelector(MagicSpendPlusMinusHalf.AlreadyUsed.selector));
        magicSpendPlusMinusHalf.withdraw(request, signature);
    }

    function test_RevertWhen_WithdrawRequestTransferFailed() external {
        address asset = address(0);

        vm.chainId(withdrawChainId);

        Request memory request = Request({
            withdrawChainId: withdrawChainId,
            claimChainId: claimChainId,
            amount: amount,
            fee: fee,
            asset: asset,
            recipient: RECIPIENT,
            preCalls: new CallStruct[](0),
            postCalls: new CallStruct[](0),
            validUntil: 0,
            validAfter: 0,
            unstakeDelaySec: 0
        });

        bytes memory signature = signWithdrawRequest(request, signerKey);

        // should throw when ETH withdraw request could not be fulfilled due to insufficient funds.
        vm.expectRevert(abi.encodeWithSelector(LiquidityManager.InsufficientLiquidity.selector, asset));
        magicSpendPlusMinusHalf.withdraw(request, signature);

        // should throw when ERC20 withdraw request could not be fulfilled due to insufficient funds.
        request.asset = address(token);
        signature = signWithdrawRequest(request, signerKey);

        vm.expectRevert(abi.encodeWithSelector(LiquidityManager.InsufficientLiquidity.selector, address(token)));
        magicSpendPlusMinusHalf.withdraw(request, signature);
    }

    function test_RevertWhen_PreCallReverts() external {
        _deposit(address(0), amount);
        _addStake(address(token), amount);
        vm.chainId(withdrawChainId);

        address asset = address(0);

        string memory revertMessage = "MAGIC";

        Request memory request = Request({
            withdrawChainId: withdrawChainId,
            claimChainId: claimChainId,
            amount: amount,
            fee: fee,
            asset: asset,
            recipient: RECIPIENT,
            preCalls: new CallStruct[](1),
            postCalls: new CallStruct[](0),
            validUntil: 0,
            validAfter: 0,
            unstakeDelaySec: 0
        });
        // force a revert by calling non existant function
        request.preCalls[0] = CallStruct({
            to: address(forceReverter),
            data: abi.encodeWithSignature("forceRevertWithMessage(string)", revertMessage),
            value: 0
        });


        bytes memory signature = signWithdrawRequest(request, signerKey);

        bytes memory revertBytes = abi.encodeWithSelector(ForceReverter.RevertWithMsg.selector, revertMessage);
        vm.expectRevert(abi.encodeWithSelector(MagicSpendPlusMinusHalf.PreCallReverted.selector, revertBytes));
        magicSpendPlusMinusHalf.withdraw(request, signature);
    }

    function test_RevertWhen_PostCallReverts() external {
        _deposit(address(0), amount);
        _addStake(address(token), amount);
        vm.chainId(withdrawChainId);

        address asset = address(0);

        string memory revertMessage = "MAGIC";

        Request memory request = Request({
            withdrawChainId: withdrawChainId,
            claimChainId: claimChainId,
            amount: amount,
            fee: fee,
            asset: asset,
            recipient: RECIPIENT,
            preCalls: new CallStruct[](0),
            postCalls: new CallStruct[](1),
            validUntil: 0,
            validAfter: 0,
            unstakeDelaySec: 0
        });
        // force a revert by calling non existant function
        request.postCalls[0] = CallStruct({
            to: address(forceReverter),
            data: abi.encodeWithSignature("forceRevertWithMessage(string)", revertMessage),
            value: 0
        });

        bytes memory signature = signWithdrawRequest(request, signerKey);

        bytes memory revertBytes = abi.encodeWithSelector(ForceReverter.RevertWithMsg.selector, revertMessage);
        vm.expectRevert(abi.encodeWithSelector(MagicSpendPlusMinusHalf.PostCallReverted.selector, revertBytes));
        magicSpendPlusMinusHalf.withdraw(request, signature);
    }

    function testClaimNativeTokenSuccess() external {
        _addStake(address(0), amount + fee);

        address asset = address(0);

        Request memory request = Request({
            withdrawChainId: withdrawChainId,
            claimChainId: claimChainId,
            amount: amount,
            fee: fee,
            asset: asset,
            recipient: RECIPIENT,
            preCalls: new CallStruct[](0),
            postCalls: new CallStruct[](0),
            validUntil: 0,
            validAfter: 0,
            unstakeDelaySec: 0
        });

        vm.chainId(claimChainId);

        bytes memory signature = signWithdrawRequest(request, aliceKey);

        vm.expectEmit(address(magicSpendPlusMinusHalf));
        emit MagicSpendPlusMinusHalf.RequestExecuted(
            RequestExecutionType.CLAIMED,
            magicSpendPlusMinusHalf.getHash(request)
        );

        magicSpendPlusMinusHalf.claim(
            request,
            signature
        );
        vm.assertEq(
            magicSpendPlusMinusHalf.stakeOf(alice, asset),
            0 ether,
            "Alice should lose her stake after claim"
        );
    }

    function testClaimERC20TokenSuccess() external {
        address asset = address(token);
        _addStake(asset, amount + fee);

        Request memory request = Request({
            withdrawChainId: withdrawChainId,
            claimChainId: claimChainId,
            amount: amount,
            fee: fee,
            asset: asset,
            recipient: RECIPIENT,
            preCalls: new CallStruct[](0),
            postCalls: new CallStruct[](0),
            validUntil: 0,
            validAfter: 0,
            unstakeDelaySec: 0
        });

        vm.chainId(withdrawChainId);
        bytes memory signature = signWithdrawRequest(request, aliceKey);

        vm.expectEmit(address(magicSpendPlusMinusHalf));
        emit MagicSpendPlusMinusHalf.RequestExecuted(
            RequestExecutionType.CLAIMED,
            magicSpendPlusMinusHalf.getHash(request)
        );

        magicSpendPlusMinusHalf.claim(
            request,
            signature
        );
        vm.assertEq(
            magicSpendPlusMinusHalf.stakeOf(alice, asset),
            0 ether,
            "Alice should lose her stake after claim"
        );
    }

    // // = = = Helpers = = =

    function signWithdrawRequest(Request memory request, uint256 signingKey)
        internal
        view
        returns (bytes memory signature)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signingKey, magicSpendPlusMinusHalf.getHash(request));
        return abi.encodePacked(r, s, v);
    }

    function _deposit(
        address asset,
        uint128 amount_
    ) internal {
        vm.prank(signer);

        magicSpendPlusMinusHalf.addLiquidity{
            value: asset == address(0) ? amount_ : 0
        }(asset, amount_);

        vm.stopPrank();
    }

    function _addStake(
        address asset,
        uint128 amount_
    ) internal {
        vm.prank(alice);

        magicSpendPlusMinusHalf.addStake{
            value: asset == address(0) ? amount_ : 0
        }(asset, amount_, 1);

        vm.stopPrank();
    }
}
