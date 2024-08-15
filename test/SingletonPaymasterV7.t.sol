// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Test, console} from "forge-std/Test.sol";
import {MessageHashUtils} from "openzeppelin-contracts-v5.0.2/contracts/utils/cryptography/MessageHashUtils.sol";
import {IERC20} from "openzeppelin-contracts-v5.0.2/contracts/token/ERC20/IERC20.sol";

import {IEntryPoint} from "@account-abstraction-v7/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction-v7/interfaces/PackedUserOperation.sol";
import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";

import {ERC20PostOpContext, BaseSingletonPaymaster} from "../src/base/BaseSingletonPaymaster.sol";
import {SingletonPaymasterV7} from "../src/SingletonPaymasterV7.sol";
import {PostOpMode} from "../src/interfaces/PostOpMode.sol";

import {SimpleAccountFactory, SimpleAccount} from "./utils/account-abstraction/v07/samples/SimpleAccountFactory.sol";
import {EntryPoint} from "./utils/account-abstraction/v07/core/EntryPoint.sol";
import {TestERC20} from "./utils/TestERC20.sol";
import {TestCounter} from "./utils/TestCounter.sol";

struct SignatureData {
    uint8 v;
    bytes32 r;
    bytes32 s;
}

struct PaymasterData {
    address paymasterAddress;
    uint128 preVerificationGas;
    uint128 postOpGas;
    uint48 validUntil;
    uint48 validAfter;
}

contract SingletonPaymasterV7Test is Test {
    // helpers
    uint8 immutable VERIFYING_MODE = 0;
    uint8 immutable ERC20_MODE = 1;
    uint256 immutable EXCHANGE_RATE = 3000 * 1e18;
    uint128 immutable POSTOP_GAS = 50_000;

    address payable beneficiary;
    address paymasterOwner;
    address paymasterSigner;
    uint256 paymasterSignerKey;
    uint256 unauthorizedSignerKey;
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
        paymasterOwner = makeAddr("paymasterOwner");
        (paymasterSigner, paymasterSignerKey) = makeAddrAndKey("paymasterSigner");
        (, unauthorizedSignerKey) = makeAddrAndKey("unauthorizedSigner");
        (user, userKey) = makeAddrAndKey("user");

        entryPoint = new EntryPoint();
        accountFactory = new SimpleAccountFactory(entryPoint);
        account = accountFactory.createAccount(user, 0);

        paymaster = new SingletonPaymasterV7(address(entryPoint), paymasterOwner, new address[](0));
        paymaster.deposit{value: 100e18}();

        vm.prank(paymasterOwner);
        paymaster.addSigner(paymasterSigner);
    }

    function testDeployment() external {
        SingletonPaymasterV7 subject = new SingletonPaymasterV7(address(entryPoint), paymasterOwner, new address[](0));
        vm.prank(paymasterOwner);
        subject.addSigner(paymasterSigner);

        assertEq(subject.owner(), paymasterOwner);
        assertEq(subject.treasury(), paymasterOwner);
        assertTrue(subject.signers(paymasterSigner));
    }

    function testERC20Success() external {
        setupERC20Environment();

        // treasury should have no tokens
        assertEq(token.balanceOf(paymasterOwner), 0);

        PackedUserOperation memory op = fillUserOp();
        op.paymasterAndData = getSignedPaymasterData(ERC20_MODE, op);
        op.signature = signUserOp(op, userKey);

        // check that UserOperationSponsored log is emitted.
        // event data check is skipped because we don't know how much will be spent.
        vm.expectEmit(true, true, true, false, address(paymaster));
        emit BaseSingletonPaymaster.UserOperationSponsored(
            getOpHash(op), op.sender, ERC20_MODE, address(token), 0, EXCHANGE_RATE
        );

        submitUserOp(op);

        // treasury should now have tokens
        assertGt(token.balanceOf(paymasterOwner), 0);
    }

    function testVerifyingSuccess() external {
        PackedUserOperation memory op = fillUserOp();
        op.paymasterAndData = getSignedPaymasterData(VERIFYING_MODE, op);
        op.signature = signUserOp(op, userKey);

        // check that UserOperationSponsored log is emitted.
        vm.expectEmit(address(paymaster));
        emit BaseSingletonPaymaster.UserOperationSponsored(getOpHash(op), op.sender, VERIFYING_MODE, address(0), 0, 0);

        submitUserOp(op);
    }

    function test_RevertWhen_ERC20PaymasterSignatureInvalid() external {
        PackedUserOperation memory op = fillUserOp();

        // sign with random private key to force false signature

        PaymasterData memory data = PaymasterData(address(paymaster), 50_000, 100_000, 0, 0);
        op.paymasterAndData =
            getERC20ModeData(data, address(token), POSTOP_GAS, EXCHANGE_RATE, op, unauthorizedSignerKey);
        op.signature = signUserOp(op, userKey);

        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, uint256(0), "AA34 signature error"));
        submitUserOp(op);
    }

    function test_RevertWhen_VerifyingPaymasterSignatureInvalid() external {
        PackedUserOperation memory op = fillUserOp();

        PaymasterData memory data = PaymasterData(address(paymaster), 50_000, 100_000, 0, 0);
        op.paymasterAndData = getVerifyingModeData(data, op, unauthorizedSignerKey);
        op.signature = signUserOp(op, userKey);

        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, uint256(0), "AA34 signature error"));
        submitUserOp(op);
    }

    function test_RevertWhen_PaymasterModeInvalid(uint8 _invalidMode) external {
        vm.assume(_invalidMode != ERC20_MODE && _invalidMode != VERIFYING_MODE);

        PackedUserOperation memory op = fillUserOp();

        op.paymasterAndData = abi.encodePacked(address(paymaster), uint128(100000), uint128(50000), _invalidMode);
        op.signature = signUserOp(op, userKey);
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                uint256(0),
                string("AA33 reverted"),
                abi.encodeWithSelector(BaseSingletonPaymaster.PaymasterModeInvalid.selector)
            )
        );
        submitUserOp(op);
    }

    function test_RevertWhen_PaymasterConfigLengthInvalid(uint8 _mode, bytes calldata _randomBytes) external {
        uint8 mode = uint8(bound(_mode, 0, 1));
        setupERC20Environment();

        if (mode == VERIFYING_MODE) {
            vm.assume(_randomBytes.length < 12);
        }

        if (mode == ERC20_MODE) {
            vm.assume(_randomBytes.length < 80);
        }

        PackedUserOperation memory op = fillUserOp();

        op.paymasterAndData = abi.encodePacked(address(paymaster), uint128(100000), uint128(50000), mode, _randomBytes);
        op.signature = signUserOp(op, userKey);
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                uint256(0),
                string("AA33 reverted"),
                abi.encodeWithSelector(BaseSingletonPaymaster.PaymasterConfigLengthInvalid.selector)
            )
        );
        submitUserOp(op);
    }

    function test_RevertWhen_PaymasterSignatureLengthInvalid(uint8 _mode) external {
        uint8 mode = uint8(bound(_mode, 0, 1));
        setupERC20Environment();

        PackedUserOperation memory op = fillUserOp();

        if (mode == VERIFYING_MODE) {
            op.paymasterAndData = abi.encodePacked(
                address(paymaster), // paymaster
                uint128(100000), // paymaster verification gas
                uint128(50000), // paymaster postop gas
                mode, // mode
                uint48(0), // validUntil
                uint48(0), // validAfter
                "BYTES WITH INVALID SIGNATURE LENGTH"
            );
        }

        if (mode == ERC20_MODE) {
            op.paymasterAndData = abi.encodePacked(
                address(paymaster), // paymaster
                uint128(100000), // paymaster verification gas
                uint128(50000), // paymaster postop gas
                mode, // mode
                uint48(0), // validUntil
                int48(0), // validAfter
                address(token), // token
                uint128(1), // postOpGas
                uint256(1), // exchangeRate
                "BYTES WITH INVALID SIGNATURE LENGTH"
            );
        }

        op.signature = signUserOp(op, userKey);
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                uint256(0),
                string("AA33 reverted"),
                abi.encodeWithSelector(BaseSingletonPaymaster.PaymasterSignatureLengthInvalid.selector)
            )
        );
        submitUserOp(op);
    }

    function test_RevertWhen_TokenAddressInvalid() external {
        setupERC20Environment();

        PackedUserOperation memory op = fillUserOp();

        op.paymasterAndData = abi.encodePacked(
            address(paymaster),
            uint128(100000),
            uint128(50000),
            ERC20_MODE,
            uint48(0),
            int48(0),
            address(0), // will throw here, token address cannot be zero.
            uint128(0),
            uint256(1),
            "DummySignature"
        );

        op.signature = signUserOp(op, userKey);
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                uint256(0),
                string("AA33 reverted"),
                abi.encodeWithSelector(BaseSingletonPaymaster.TokenAddressInvalid.selector)
            )
        );
        submitUserOp(op);
    }

    function test_RevertWhen_ExchangeRateInvalid() external {
        setupERC20Environment();

        PackedUserOperation memory op = fillUserOp();

        op.paymasterAndData = abi.encodePacked(
            address(paymaster),
            uint128(100000),
            uint128(50000),
            ERC20_MODE,
            uint48(0),
            int48(0),
            address(token),
            uint128(0),
            uint256(0), // will throw here, price cannot be zero.
            "DummySignature"
        );

        op.signature = signUserOp(op, userKey);
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                uint256(0),
                "AA33 reverted",
                abi.encodeWithSelector(BaseSingletonPaymaster.ExchangeRateInvalid.selector)
            )
        );
        submitUserOp(op);
    }

    function test_RevertWhen_PaymasterAndDataLengthInvalid() external {
        setupERC20Environment();

        PackedUserOperation memory op = fillUserOp();

        op.paymasterAndData = abi.encodePacked(address(paymaster), uint128(100000), uint128(50000));

        op.signature = signUserOp(op, userKey);
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                uint256(0),
                "AA33 reverted",
                abi.encodeWithSelector(BaseSingletonPaymaster.PaymasterAndDataLengthInvalid.selector)
            )
        );
        submitUserOp(op);
    }

    function test_RevertWhen_PostOpTransferFromFailed() external {
        PackedUserOperation memory op = fillUserOp();

        op.paymasterAndData = getSignedPaymasterData(ERC20_MODE, op);
        op.signature = signUserOp(op, userKey);

        vm.expectEmit(address(entryPoint));
        emit IEntryPoint.PostOpRevertReason(
            getOpHash(op),
            op.sender,
            0,
            abi.encodeWithSelector(
                IEntryPoint.PostOpReverted.selector, abi.encodeWithSelector(SafeTransferLib.TransferFromFailed.selector)
            )
        );

        submitUserOp(op);
    }

    // test that the treasury receives funds when postOp is called
    function test_postOpCalculation(
        uint256 _exchangeRate,
        uint128 _postOpGas,
        uint256 _userOperationGasUsed,
        uint256 _actualUserOpFeePerGas
    ) external {
        token.sudoMint(address(account), 1e50);
        token.sudoApprove(address(account), address(paymaster), UINT256_MAX);

        uint128 postOpGas = uint128(bound(_postOpGas, 21_000, 250_000));
        uint256 actualUserOpFeePerGas = bound(_actualUserOpFeePerGas, 0.01 gwei, 5000 gwei);
        uint256 userOperationGasUsed = bound(_userOperationGasUsed, 21_000, 30_000_000);
        uint256 exchangeRate = bound(_exchangeRate, 1e6, 1e20);

        uint256 actualGasCost = userOperationGasUsed * actualUserOpFeePerGas;

        bytes memory context = abi.encode(
            ERC20PostOpContext({
                sender: address(account),
                token: address(token),
                exchangeRate: exchangeRate,
                postOpGas: postOpGas,
                userOpHash: 0x0000000000000000000000000000000000000000000000000000000000000000,
                maxFeePerGas: 0,
                maxPriorityFeePerGas: 0
            })
        );

        vm.prank(address(entryPoint));
        paymaster.postOp(PostOpMode.opSucceeded, context, actualGasCost, actualUserOpFeePerGas);
        uint256 expectedCostInToken =
            paymaster.getCostInToken(actualGasCost, postOpGas, actualUserOpFeePerGas, exchangeRate);

        vm.assertEq(expectedCostInToken, token.balanceOf(paymaster.treasury()));
    }

    function test_RevertWhen_NonEntryPointCaller() external {
        vm.expectRevert("Sender not EntryPoint");
        paymaster.postOp(
            PostOpMode.opSucceeded,
            abi.encodePacked(address(account), address(token), uint256(5), bytes32(0), uint256(0), uint256(0)),
            0,
            0
        );

        PackedUserOperation memory op = fillUserOp();
        bytes32 opHash = getOpHash(op);
        vm.expectRevert("Sender not EntryPoint");
        paymaster.validatePaymasterUserOp(op, opHash, 0);
    }

    // context should always be empty when used in verfiying mode
    function test_veryfingValidatePaymasterUserOp(
        uint48 _validUntil,
        uint48 _validAfter,
        uint128 _paymasterPostOpGas,
        uint128 _paymasterVerificationGas
    ) external {
        PackedUserOperation memory op = fillUserOp();
        PaymasterData memory data =
            PaymasterData(address(paymaster), _paymasterVerificationGas, _paymasterPostOpGas, _validUntil, _validAfter);

        op.paymasterAndData = getVerifyingModeData(data, op, paymasterSignerKey);
        op.signature = signUserOp(op, userKey);
        bytes32 opHash = getOpHash(op);

        vm.prank(address(entryPoint));
        (bytes memory context, uint256 validationData) = paymaster.validatePaymasterUserOp(op, opHash, 0);
        vm.assertEq(uint160(validationData), 0);
        vm.assertEq(context, "", "context should always be empty when used in verifying mode");
    }

    // context and validation data should be properly encoded in Verifying mode.
    // should not revert when a invalid signature is presented (requirement by entryPoint so that bundler can run simulations)
    function test_verifyingValidatePaymasterUserOp(uint48 _validUntil, uint48 _validAfter) external {
        PackedUserOperation memory op = fillUserOp();
        PaymasterData memory data = PaymasterData(address(paymaster), 50_000, 100_000, _validUntil, _validAfter);

        // Test with correct signature
        verifyingValidateOpHelper(op, data, paymasterSignerKey, 0);

        // Test with incorrect signature
        verifyingValidateOpHelper(op, data, unauthorizedSignerKey, 1);
    }

    function verifyingValidateOpHelper(
        PackedUserOperation memory op,
        PaymasterData memory data,
        uint256 signerKey,
        uint160 expectedSignature
    ) internal {
        op.paymasterAndData = getVerifyingModeData(data, op, signerKey);
        op.signature = signUserOp(op, userKey);
        bytes32 opHash = getOpHash(op);

        vm.prank(address(entryPoint));
        (bytes memory context, uint256 validationData) = paymaster.validatePaymasterUserOp(op, opHash, 0);

        vm.assertEq(uint160(validationData), expectedSignature, "unexpected signature");
        vm.assertEq(uint48(validationData >> 160), data.validUntil);
        vm.assertEq(uint48(validationData >> (48 + 160)), data.validAfter);
        vm.assertEq(context, "", "context should always be empty when used in verifying mode");
    }

    // context and validation data should be properly populated and encoded in ERC-20 mode
    // should not revert when a invalid signature is presented (requirement by entryPoint so that bundler can run simulations)
    function test_ERC20ValidatePaymasterUserOp(
        uint48 _validUntil,
        uint48 _validAfter,
        address _token,
        uint128 _postOpGas,
        uint256 _exchangeRate
    ) external {
        vm.assume(_exchangeRate > 0);
        vm.assume(_token != address(0));

        PackedUserOperation memory op = fillUserOp();
        PaymasterData memory data = PaymasterData(address(paymaster), 50_000, 100_000, _validUntil, _validAfter);

        // Test with correct signature
        validateERC20PaymasterUserOp(op, data, _token, _postOpGas, _exchangeRate, 0, paymasterSignerKey);

        // Test with incorrect signature
        validateERC20PaymasterUserOp(op, data, _token, _postOpGas, _exchangeRate, 1, unauthorizedSignerKey);
    }

    function validateERC20PaymasterUserOp(
        PackedUserOperation memory op,
        PaymasterData memory data,
        address tokenAddress,
        uint128 postOpGas,
        uint256 exchangeRate,
        uint160 expectedSignature,
        uint256 signerKey
    ) internal {
        op.paymasterAndData = getERC20ModeData(data, tokenAddress, postOpGas, exchangeRate, op, signerKey);
        op.signature = signUserOp(op, userKey);
        bytes32 opHash = getOpHash(op);

        vm.prank(address(entryPoint));
        (bytes memory context, uint256 validationData) = paymaster.validatePaymasterUserOp(op, opHash, 0);

        // Validation checks
        vm.assertEq(uint160(validationData), expectedSignature, "unexpected signature");
        vm.assertEq(uint48(validationData >> 160), data.validUntil);
        vm.assertEq(uint48(validationData >> (48 + 160)), data.validAfter);

        // Context checks
        ERC20PostOpContext memory ctx = abi.decode(context, (ERC20PostOpContext));
        vm.assertEq(ctx.sender, op.sender, "encoded context sender should equal userOperation.sender");
        vm.assertEq(ctx.token, tokenAddress, "encoded context token should equal token");
        vm.assertEq(ctx.exchangeRate, exchangeRate, "encoded context exchangeRate should equal exchangeRate");
        vm.assertEq(ctx.postOpGas, postOpGas, "encoded context postOpGas should equal postOpGas");
        vm.assertEq(ctx.userOpHash, opHash, "encoded context opHash should equal opHash");
        vm.assertEq(ctx.maxFeePerGas, 0, "encoded context maxFeePerGas should equal to 0");
        vm.assertEq(ctx.maxPriorityFeePerGas, 0, "encoded context maxPriorityFeePerGas should equal to 0");
    }

    function testValidateSignatureCorrectness() external {
        flipUserOperationBitsAndValidateSignature(ERC20_MODE);
        flipUserOperationBitsAndValidateSignature(VERIFYING_MODE);
    }

    // HELPERS //

    function flipUserOperationBitsAndValidateSignature(uint8 _mode) internal {
        PackedUserOperation memory op = fillUserOp();
        op.paymasterAndData = getSignedPaymasterData(_mode, op);
        op.signature = signUserOp(op, userKey);

        checkIsPaymasterSignatureValid(op, true);

        // flip each bit in userOperation and check that signature is invalid
        for (uint256 bitPosition = 0; bitPosition < 256; bitPosition++) {
            uint256 mask = 1 << bitPosition;

            if (bitPosition < 160) {
                op.sender = address(bytes20(op.sender) ^ bytes20(uint160(mask)));
                checkIsPaymasterSignatureValid(op, false);
                op.sender = address(bytes20(op.sender) ^ bytes20(uint160(mask)));
            }

            op.nonce = uint256(bytes32(op.nonce) ^ bytes32(mask));
            checkIsPaymasterSignatureValid(op, false);
            op.nonce = uint256(bytes32(op.nonce) ^ bytes32(mask));

            op.accountGasLimits = bytes32(op.accountGasLimits) ^ bytes32(mask);
            checkIsPaymasterSignatureValid(op, false);
            op.accountGasLimits = bytes32(op.accountGasLimits) ^ bytes32(mask);

            op.preVerificationGas = uint256(bytes32(op.preVerificationGas) ^ bytes32(mask));
            checkIsPaymasterSignatureValid(op, false);
            op.preVerificationGas = uint256(bytes32(op.preVerificationGas) ^ bytes32(mask));

            op.gasFees = bytes32(op.gasFees) ^ bytes32(mask);
            checkIsPaymasterSignatureValid(op, false);
            op.gasFees = bytes32(op.gasFees) ^ bytes32(mask);
        }

        // check calldata
        for (uint256 byteIndex = 0; byteIndex < op.callData.length; byteIndex++) {
            for (uint8 bitPosition = 0; bitPosition < 8; bitPosition++) {
                uint256 mask = 1 << bitPosition;

                op.callData[byteIndex] = bytes1(uint8(op.callData[byteIndex]) ^ uint8(mask));
                checkIsPaymasterSignatureValid(op, false);
                op.callData[byteIndex] = bytes1(uint8(op.callData[byteIndex]) ^ uint8(mask));
            }
        }

        // check initCode
        for (uint256 byteIndex = 0; byteIndex < op.initCode.length; byteIndex++) {
            for (uint8 bitPosition = 0; bitPosition < 8; bitPosition++) {
                uint256 mask = 1 << bitPosition;

                op.initCode[byteIndex] = bytes1(uint8(op.initCode[byteIndex]) ^ uint8(mask));
                checkIsPaymasterSignatureValid(op, false);
                op.initCode[byteIndex] = bytes1(uint8(op.initCode[byteIndex]) ^ uint8(mask));
            }
        }

        for (uint256 byteIndex = 0; byteIndex < op.paymasterAndData.length - 66; byteIndex++) {
            for (uint8 bitPosition = 0; bitPosition < 8; bitPosition++) {
                uint256 mask = 1 << bitPosition;

                // we don't want to flip the mode byte
                if (byteIndex == 20 + 32) {
                    continue;
                }

                op.paymasterAndData[byteIndex] = bytes1(uint8(op.paymasterAndData[byteIndex]) ^ uint8(mask));
                checkIsPaymasterSignatureValid(op, false);
                op.paymasterAndData[byteIndex] = bytes1(uint8(op.paymasterAndData[byteIndex]) ^ uint8(mask));
            }
        }
    }

    function checkIsPaymasterSignatureValid(PackedUserOperation memory op, bool isSignatureValid) internal {
        bytes32 opHash = getOpHash(op);
        vm.prank(address(entryPoint));
        (, uint256 validationData) = paymaster.validatePaymasterUserOp(op, opHash, 0);
        assertEq(uint160(validationData), isSignatureValid ? 0 : 1);
    }

    function getSignedPaymasterData(uint8 mode, PackedUserOperation memory userOp)
        private
        view
        returns (bytes memory)
    {
        PaymasterData memory data = PaymasterData({
            paymasterAddress: address(paymaster),
            preVerificationGas: 100_000,
            postOpGas: 50_000,
            validUntil: 0,
            validAfter: 0
        });

        if (mode == VERIFYING_MODE) {
            return getVerifyingModeData(data, userOp, paymasterSignerKey);
        } else if (mode == ERC20_MODE) {
            return getERC20ModeData(data, address(token), POSTOP_GAS, EXCHANGE_RATE, userOp, paymasterSignerKey);
        }

        revert("unexpected mode");
    }

    function getVerifyingModeData(PaymasterData memory data, PackedUserOperation memory userOp, uint256 signerKey)
        private
        view
        returns (bytes memory)
    {
        userOp.paymasterAndData = abi.encodePacked(
            data.paymasterAddress,
            data.preVerificationGas,
            data.postOpGas,
            VERIFYING_MODE,
            data.validUntil,
            data.validAfter
        );
        bytes32 hash = paymaster.getHash(VERIFYING_MODE, userOp);
        bytes memory sig = getSignature(hash, signerKey);

        return abi.encodePacked(
            data.paymasterAddress,
            data.preVerificationGas,
            data.postOpGas,
            VERIFYING_MODE,
            data.validUntil,
            data.validAfter,
            sig
        );
    }

    function getERC20ModeData(
        PaymasterData memory data,
        address erc20,
        uint128 postOpGas,
        uint256 exchangeRate,
        PackedUserOperation memory userOp,
        uint256 signingKey
    ) private view returns (bytes memory) {
        userOp.paymasterAndData = abi.encodePacked(
            data.paymasterAddress,
            data.preVerificationGas,
            data.postOpGas,
            ERC20_MODE,
            data.validUntil,
            data.validAfter,
            erc20,
            postOpGas,
            exchangeRate
        );
        bytes32 hash = paymaster.getHash(ERC20_MODE, userOp);
        bytes memory sig = getSignature(hash, signingKey);

        return abi.encodePacked(
            data.paymasterAddress,
            data.preVerificationGas,
            data.postOpGas,
            ERC20_MODE,
            data.validUntil,
            data.validAfter,
            erc20,
            postOpGas,
            exchangeRate,
            sig
        );
    }

    function getSignature(bytes32 hash, uint256 signingKey) private pure returns (bytes memory) {
        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(hash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signingKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function fillUserOp() private view returns (PackedUserOperation memory op) {
        op.sender = address(account);
        op.nonce = entryPoint.getNonce(address(account), 0);
        op.callData = abi.encodeWithSelector(
            SimpleAccount.execute.selector, address(counter), 0, abi.encodeWithSelector(TestCounter.count.selector)
        );
        op.accountGasLimits = bytes32(abi.encodePacked(bytes16(uint128(80000)), bytes16(uint128(50000))));
        op.preVerificationGas = 50000;
        op.gasFees = bytes32(abi.encodePacked(bytes16(uint128(100)), bytes16(uint128(1000000000))));
        op.signature = signUserOp(op, userKey);
        return op;
    }

    function getOpHash(PackedUserOperation memory op) internal view returns (bytes32) {
        return entryPoint.getUserOpHash(op);
    }

    function signUserOp(PackedUserOperation memory op, uint256 _key) private view returns (bytes memory signature) {
        bytes32 hash = entryPoint.getUserOpHash(op);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_key, MessageHashUtils.toEthSignedMessageHash(hash));
        signature = abi.encodePacked(r, s, v);
    }

    function submitUserOp(PackedUserOperation memory op) public {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);
    }

    function setupERC20Environment() private {
        token.sudoMint(address(account), 1000e18);
        token.sudoMint(address(paymaster), 1);
        token.sudoApprove(address(account), address(paymaster), UINT256_MAX);
    }
}
