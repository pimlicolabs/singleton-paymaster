// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { Test, console2 } from "forge-std/Test.sol";
import { MessageHashUtils } from "openzeppelin-contracts-v5.0.2/contracts/utils/cryptography/MessageHashUtils.sol";
import { ERC20 } from "openzeppelin-contracts-v5.0.2/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin-v4.8.3/contracts/utils/cryptography/ECDSA.sol";

import { UserOperation } from "account-abstraction-v6/interfaces/UserOperation.sol";
import { IEntryPoint } from "account-abstraction-v7/interfaces/IEntryPoint.sol";

import { PostOpMode } from "../src/interfaces/PostOpMode.sol";
import { ERC20PostOpContext, BaseSingletonPaymaster } from "../src/base/BaseSingletonPaymaster.sol";
import { SingletonPaymasterV6 } from "../src/SingletonPaymasterV6.sol";

import { EntryPoint } from "./utils/account-abstraction/v06/core/EntryPoint.sol";
import { TestERC20 } from "./utils/TestERC20.sol";
import { TestCounter } from "./utils/TestCounter.sol";
import { SimpleAccountFactory, SimpleAccount } from "./utils/account-abstraction/v06/samples/SimpleAccountFactory.sol";

using ECDSA for bytes32;

struct SignatureData {
    uint8 v;
    bytes32 r;
    bytes32 s;
}

struct PaymasterData {
    address paymasterAddress;
    uint48 validUntil;
    uint48 validAfter;
    bool allowAllBundlers;
}

contract SingletonPaymasterV6Test is Test {
    uint8 immutable VERIFYING_MODE = 0;
    uint8 immutable ERC20_MODE = 1;
    bool immutable ALLOW_ALL_BUNDLERS = true;
    bool immutable ALLOW_WHITELISTED_BUNDLERS = false;
    uint256 immutable EXCHANGE_RATE = 3000 * 1e18;
    uint128 immutable POSTOP_GAS = 50_000;

    address payable beneficiary;
    address paymasterOwner;
    address paymasterSigner;
    address treasury;
    uint256 paymasterSignerKey;
    uint256 unauthorizedSignerKey;
    address user;
    uint256 userKey;

    SingletonPaymasterV6 paymaster;
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
        treasury = makeAddr("treasury");
        (paymasterSigner, paymasterSignerKey) = makeAddrAndKey("paymasterSigner");
        (, unauthorizedSignerKey) = makeAddrAndKey("unauthorizedSigner");
        (user, userKey) = makeAddrAndKey("user");

        entryPoint = new EntryPoint();
        accountFactory = new SimpleAccountFactory(entryPoint);
        account = accountFactory.createAccount(user, 0);

        paymaster = new SingletonPaymasterV6(address(entryPoint), paymasterOwner, new address[](0));
        paymaster.deposit{ value: 100e18 }();

        vm.prank(paymasterOwner);
        paymaster.addSigner(paymasterSigner);
    }

    function testDeployment() external {
        SingletonPaymasterV6 subject = new SingletonPaymasterV6(address(entryPoint), paymasterOwner, new address[](0));
        vm.prank(paymasterOwner);
        subject.addSigner(paymasterSigner);

        assertEq(subject.owner(), paymasterOwner);
        assertTrue(subject.signers(paymasterSigner));
    }

    function testERC20Success() external {
        setupERC20Environment();

        // treasury should have no tokens
        assertEq(token.balanceOf(treasury), 0);

        UserOperation memory op = fillUserOp();
        op.paymasterAndData = getSignedPaymasterData(ERC20_MODE, ALLOW_ALL_BUNDLERS, op);
        op.signature = signUserOp(op, userKey);

        // check that UserOperationSponsored log is emitted.
        // event data check is skipped because we don't know how much will be spent.
        vm.expectEmit(true, true, true, false, address(paymaster));
        emit BaseSingletonPaymaster.UserOperationSponsored(
            getOpHash(op), op.sender, ERC20_MODE, address(token), 0, EXCHANGE_RATE
        );

        submitUserOp(op);

        // treasury should now have tokens
        assertGt(token.balanceOf(treasury), 0);
    }

    function testVerifyingSuccess() external {
        UserOperation memory op = fillUserOp();
        op.paymasterAndData = getSignedPaymasterData(VERIFYING_MODE, ALLOW_ALL_BUNDLERS, op);
        op.signature = signUserOp(op, userKey);

        // check that UserOperationSponsored log is emitted.
        vm.expectEmit(address(paymaster));
        emit BaseSingletonPaymaster.UserOperationSponsored(getOpHash(op), op.sender, VERIFYING_MODE, address(0), 0, 0);

        submitUserOp(op);
    }

    function test_RevertWhen_ERC20PaymasterSignatureInvalid() external {
        UserOperation memory op = fillUserOp();

        // sign with random private key to force false signature
        PaymasterData memory data = PaymasterData(address(paymaster), 0, 0, ALLOW_ALL_BUNDLERS);
        op.paymasterAndData =
            getERC20ModeData(data, address(token), POSTOP_GAS, EXCHANGE_RATE, uint128(0), op, unauthorizedSignerKey);
        op.signature = signUserOp(op, userKey);

        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, uint256(0), "AA34 signature error"));
        submitUserOp(op);
    }

    function test_RevertWhen_VerifyingPaymasterSignatureInvalid() external {
        UserOperation memory op = fillUserOp();

        // sign with random private key to force false signature
        PaymasterData memory data = PaymasterData(address(paymaster), 0, 0, ALLOW_ALL_BUNDLERS);
        op.paymasterAndData = getVerifyingModeData(data, op, unauthorizedSignerKey);
        op.signature = signUserOp(op, userKey);

        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, uint256(0), "AA34 signature error"));
        submitUserOp(op);
    }

    function testERC20LegacySuccess() external {
        setupERC20Environment();

        // on chains that don't support EIP-1559, the UserOperation's maxFee & maxPriorityFee are equal.
        UserOperation memory op = fillUserOp();
        op.maxPriorityFeePerGas = 5;
        op.maxFeePerGas = 5;
        op.paymasterAndData = getSignedPaymasterData(ERC20_MODE, ALLOW_ALL_BUNDLERS, op);
        op.signature = signUserOp(op, userKey);

        // check that UserOperationSponsored log is emitted.
        // event data check is skipped because we don't know how much will be spent.
        vm.expectEmit(true, true, true, false, address(paymaster));
        emit BaseSingletonPaymaster.UserOperationSponsored(
            getOpHash(op), op.sender, ERC20_MODE, address(token), 0, EXCHANGE_RATE
        );

        submitUserOp(op);
    }

    function test_RevertWhen_PaymasterModeInvalid(uint8 invalidMode) external {
        vm.assume(invalidMode != ERC20_MODE && invalidMode != VERIFYING_MODE);

        UserOperation memory op = fillUserOp();

        op.paymasterAndData = abi.encodePacked(address(paymaster), invalidMode, ALLOW_ALL_BUNDLERS);
        op.signature = signUserOp(op, userKey);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA33 reverted (or OOG)"));
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

        UserOperation memory op = fillUserOp();

        op.paymasterAndData = abi.encodePacked(
            address(paymaster), uint128(100_000), uint128(50_000), mode, ALLOW_ALL_BUNDLERS, _randomBytes
        );
        op.signature = signUserOp(op, userKey);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, uint256(0), "AA33 reverted (or OOG)"));
        submitUserOp(op);
    }

    function test_RevertWhen_PaymasterSignatureLengthInvalid(uint8 _mode) external {
        uint8 mode = uint8(bound(_mode, 0, 1));
        setupERC20Environment();

        UserOperation memory op = fillUserOp();

        if (mode == VERIFYING_MODE) {
            op.paymasterAndData = abi.encodePacked(
                address(paymaster),
                uint128(100_000),
                uint128(50_000),
                mode,
                ALLOW_ALL_BUNDLERS,
                uint48(0),
                int48(0),
                "BYTES WITH INVALID SIGNATURE LENGTH"
            );
        }

        if (mode == ERC20_MODE) {
            op.paymasterAndData = abi.encodePacked(
                address(paymaster),
                uint128(100_000),
                uint128(50_000),
                mode,
                ALLOW_ALL_BUNDLERS,
                uint48(0),
                int48(0),
                address(token),
                uint256(1),
                "BYTES WITH INVALID SIGNATURE LENGTH"
            );
        }

        op.signature = signUserOp(op, userKey);
        vm.expectRevert(
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, uint256(0), string("AA33 reverted (or OOG)"))
        );
        submitUserOp(op);
    }

    // ERC20 mode specific errors

    function test_RevertWhen_PostOpTransferFromFailed() external {
        UserOperation memory op = fillUserOp();

        op.paymasterAndData = getSignedPaymasterData(ERC20_MODE, ALLOW_ALL_BUNDLERS, op);
        op.signature = signUserOp(op, userKey);

        uint256 nonce = 0;
        bool userOpSuccess = false; // this is what we are checking (userOperation should be false if postOp reverts).
        vm.expectEmit(true, true, true, false, address(entryPoint));
        emit IEntryPoint.UserOperationEvent(getOpHash(op), op.sender, address(paymaster), nonce, userOpSuccess, 0, 0);

        submitUserOp(op);
    }

    function test_RevertWhen_TokenAddressInvalid() external {
        setupERC20Environment();

        UserOperation memory op = fillUserOp();

        op.paymasterAndData = abi.encodePacked(
            address(paymaster),
            ERC20_MODE,
            ALLOW_ALL_BUNDLERS,
            uint48(0), // validUntil
            int48(0), // validAfter
            address(0), // **will throw here, token address cannot be zero.**
            uint128(1), // postOpGas
            uint256(1), // exchangeRate
            uint128(0), // paymasterValidationGasLimit
            "DummySignature"
        );

        op.signature = signUserOp(op, userKey);
        vm.expectRevert(
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, uint256(0), string("AA33 reverted (or OOG)"))
        );
        submitUserOp(op);
    }

    function test_RevertWhen_ExchangeRateInvalid() external {
        UserOperation memory op = fillUserOp();
        op.paymasterAndData = abi.encodePacked(
            address(paymaster),
            ERC20_MODE,
            ALLOW_ALL_BUNDLERS,
            uint48(0), // validUntil
            uint48(0), // validAfter
            address(token), // token
            uint128(0), // postOpGas
            uint256(0), // **will throw here, exchangeRate cannot be zero.**
            "DummySignature"
        );

        op.signature = signUserOp(op, userKey);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, uint256(0), "AA33 reverted (or OOG)"));
        submitUserOp(op);
    }

    function test_RevertWhen_PaymasterAndDataLengthInvalid() external {
        UserOperation memory op = fillUserOp();
        op.paymasterAndData = abi.encodePacked(address(paymaster), uint128(100_000), uint128(50_000));
        op.signature = signUserOp(op, userKey);

        vm.expectRevert();
        submitUserOp(op);
    }

    function test_RevertWhen_NonEntryPointCaller() external {
        vm.expectRevert("Sender not EntryPoint");
        paymaster.postOp(
            PostOpMode.opSucceeded,
            abi.encodePacked(address(account), address(token), uint256(5), bytes32(0), uint256(0), uint256(0)),
            0
        );

        UserOperation memory op = fillUserOp();
        bytes32 opHash = getOpHash(op);
        vm.expectRevert("Sender not EntryPoint");
        paymaster.validatePaymasterUserOp(op, opHash, 0);
    }

    function test_RevertWhen_BundlerNotAllowed() external {
        setupERC20Environment();

        // treasury should have no tokens
        assertEq(token.balanceOf(paymasterOwner), 0);

        UserOperation memory op = fillUserOp();
        op.paymasterAndData = getSignedPaymasterData(ERC20_MODE, ALLOW_WHITELISTED_BUNDLERS, op);
        op.signature = signUserOp(op, userKey);

        // check that UserOperationSponsored log is emitted.
        // event data check is skipped because we don't know how much will be spent.
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, uint256(0), "AA33 reverted (or OOG)"));

        submitUserOp(op);
    }

    function test_RevertWhen_OnlyBundlerAllowed() external {
        setupERC20Environment();

        // treasury should have no tokens
        assertEq(token.balanceOf(treasury), 0);

        address[] memory bundlers = new address[](1);
        bundlers[0] = address(DEFAULT_SENDER);

        paymasterOwner = makeAddr("paymasterOwner");
        vm.prank(paymasterOwner);
        paymaster.updateBundlerAllowlist(bundlers, true);

        UserOperation memory op = fillUserOp();
        op.paymasterAndData = getSignedPaymasterData(ERC20_MODE, ALLOW_WHITELISTED_BUNDLERS, op);
        op.signature = signUserOp(op, userKey);

        // check that UserOperationSponsored log is emitted.
        // event data check is skipped because we don't know how much will be spent.
        vm.expectEmit(true, true, true, false, address(paymaster));
        emit BaseSingletonPaymaster.UserOperationSponsored(
            getOpHash(op), op.sender, ERC20_MODE, address(token), 0, EXCHANGE_RATE
        );

        submitUserOp(op);

        // treasury should now have tokens
        assertGt(token.balanceOf(treasury), 0);
    }

    // context and validation data should be properly encoded in Verifying mode.
    // should not revert when a invalid signature is presented (requirement by entryPoint so that bundler can run
    // simulations)
    function test_verifyingValidatePaymasterUserOp(uint48 _validUntil, uint48 _validAfter) external {
        UserOperation memory op = fillUserOp();
        PaymasterData memory data = PaymasterData(address(paymaster), _validUntil, _validAfter, ALLOW_ALL_BUNDLERS);

        // Test with correct signature
        verifyingValidateOpHelper(op, data, paymasterSignerKey, 0);

        // Test with incorrect signature
        verifyingValidateOpHelper(op, data, unauthorizedSignerKey, 1);
    }

    function verifyingValidateOpHelper(
        UserOperation memory op,
        PaymasterData memory data,
        uint256 signerKey,
        uint160 expectedSignature
    )
        internal
    {
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
    // should not revert when a invalid signature is presented (requirement by entryPoint so that bundler can run
    // simulations)
    function test_ERC20ValidatePaymasterUserOp(
        uint48 _validUntil,
        uint48 _validAfter,
        address _token,
        uint128 _postOpGas,
        uint256 _exchangeRate
    )
        external
    {
        vm.assume(_exchangeRate > 0);
        vm.assume(_token != address(0));

        UserOperation memory op = fillUserOp();
        PaymasterData memory data = PaymasterData(address(paymaster), _validUntil, _validAfter, ALLOW_ALL_BUNDLERS);

        // Test with correct signature
        validateERC20PaymasterUserOp(op, data, _token, _postOpGas, _exchangeRate, 0, paymasterSignerKey);

        // Test with incorrect signature
        validateERC20PaymasterUserOp(op, data, _token, _postOpGas, _exchangeRate, 1, unauthorizedSignerKey);
    }

    // test that the treasury receives funds when postOp is called
    function test_postOpCalculation(
        uint256 _exchangeRate,
        uint128 _postOpGas,
        uint256 _userOperationGasUsed,
        uint256 _maxFeePerGas,
        uint256 _maxPriorityFeePerGas
    )
        external
    {
        token.sudoMint(address(account), 1e50);
        token.sudoApprove(address(account), address(paymaster), UINT256_MAX);

        uint128 postOpGas = uint128(bound(_postOpGas, 21_000, 250_000));
        uint256 userOperationGasUsed = bound(_userOperationGasUsed, 21_000, 30_000_000);
        uint256 exchangeRate = bound(_exchangeRate, 1e6, 1e20);
        uint256 maxFeePerGas = bound(_maxFeePerGas, 0.01 gwei, 5000 gwei);
        uint256 maxPriorityFeePerGas = bound(_maxPriorityFeePerGas, 0.01 gwei, 5000 gwei);
        vm.assume(maxFeePerGas >= maxPriorityFeePerGas);

        uint256 actualUserOpFeePerGas;
        if (maxFeePerGas == maxPriorityFeePerGas) {
            // chains that only support legacy (pre EIP-1559 transactions)
            actualUserOpFeePerGas = maxFeePerGas;
        } else {
            actualUserOpFeePerGas = Math.min(maxFeePerGas, maxPriorityFeePerGas + block.basefee);
        }

        uint256 actualGasCost = userOperationGasUsed * actualUserOpFeePerGas;

        bytes memory context = abi.encode(
            ERC20PostOpContext({
                sender: address(account),
                token: address(token),
                treasury: address(treasury),
                exchangeRate: exchangeRate,
                postOpGas: postOpGas,
                userOpHash: 0x0000000000000000000000000000000000000000000000000000000000000000,
                maxFeePerGas: maxFeePerGas,
                maxPriorityFeePerGas: maxPriorityFeePerGas,
                executionGasLimit: uint256(0),
                preOpGasApproximation: uint256(0)
            })
        );

        vm.prank(address(entryPoint));
        paymaster.postOp(PostOpMode.opSucceeded, context, actualGasCost);
        uint256 expectedCostInToken =
            paymaster.getCostInToken(userOperationGasUsed, postOpGas, actualUserOpFeePerGas, exchangeRate);

        // TODO: Check when preOpGasApproximation is not 0
        vm.assertEq(expectedCostInToken, token.balanceOf(treasury));
    }

    function validateERC20PaymasterUserOp(
        UserOperation memory op,
        PaymasterData memory data,
        address tokenAddress,
        uint128 postOpGas,
        uint256 exchangeRate,
        uint160 expectedSignature,
        uint256 signerKey
    )
        internal
    {
        op.paymasterAndData = getERC20ModeData(data, tokenAddress, postOpGas, exchangeRate, uint128(0), op, signerKey);
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
        vm.assertEq(ctx.maxFeePerGas, op.maxFeePerGas, "encoded context maxFeePerGas should equal op.maxFeePerGas");
        vm.assertEq(
            ctx.maxPriorityFeePerGas,
            op.maxPriorityFeePerGas,
            "encoded context maxPriorityFeePerGas should equal op.maxPriorityFeePerGas"
        );
    }

    function testValidateSignatureCorrectness() external {
        flipUserOperationBitsAndValidateSignature(ERC20_MODE);
        flipUserOperationBitsAndValidateSignature(VERIFYING_MODE);
    }

    // HELPERS //

    function flipUserOperationBitsAndValidateSignature(uint8 _mode) internal {
        UserOperation memory op = fillUserOp();
        op.paymasterAndData = getSignedPaymasterData(_mode, ALLOW_ALL_BUNDLERS, op);
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

            op.callGasLimit = uint256(bytes32(op.callGasLimit) ^ bytes32(mask));
            checkIsPaymasterSignatureValid(op, false);
            op.callGasLimit = uint256(bytes32(op.callGasLimit) ^ bytes32(mask));

            op.preVerificationGas = uint256(bytes32(op.preVerificationGas) ^ bytes32(mask));
            checkIsPaymasterSignatureValid(op, false);
            op.preVerificationGas = uint256(bytes32(op.preVerificationGas) ^ bytes32(mask));

            op.verificationGasLimit = uint256(bytes32(op.verificationGasLimit) ^ bytes32(mask));
            checkIsPaymasterSignatureValid(op, false);
            op.verificationGasLimit = uint256(bytes32(op.verificationGasLimit) ^ bytes32(mask));

            op.maxFeePerGas = uint256(bytes32(op.maxFeePerGas) ^ bytes32(mask));
            checkIsPaymasterSignatureValid(op, false);
            op.maxFeePerGas = uint256(bytes32(op.maxFeePerGas) ^ bytes32(mask));

            op.maxPriorityFeePerGas = uint256(bytes32(op.maxPriorityFeePerGas) ^ bytes32(mask));
            checkIsPaymasterSignatureValid(op, false);
            op.maxPriorityFeePerGas = uint256(bytes32(op.maxPriorityFeePerGas) ^ bytes32(mask));
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

        // check calldata
        for (uint256 byteIndex = 0; byteIndex < op.callData.length; byteIndex++) {
            for (uint8 bitPosition = 0; bitPosition < 8; bitPosition++) {
                uint256 mask = 1 << bitPosition;

                op.callData[byteIndex] = bytes1(uint8(op.callData[byteIndex]) ^ uint8(mask));
                checkIsPaymasterSignatureValid(op, false);
                op.callData[byteIndex] = bytes1(uint8(op.callData[byteIndex]) ^ uint8(mask));
            }
        }

        uint256 paymasterConfigLength = 20;

        if (_mode == ERC20_MODE) {
            paymasterConfigLength += 96;
        }

        if (_mode == VERIFYING_MODE) {
            paymasterConfigLength += 12;
        }

        // check paymasterAndData
        for (uint256 byteIndex = 0; byteIndex < paymasterConfigLength; byteIndex++) {
            for (uint8 bitPosition = 0; bitPosition < 8; bitPosition++) {
                uint256 mask = 1 << bitPosition;

                // we don't want to flip the mode byte and allowAllBundlers byte
                if (byteIndex == 20 || byteIndex == 21) {
                    continue;
                }

                op.paymasterAndData[byteIndex] = bytes1(uint8(op.paymasterAndData[byteIndex]) ^ uint8(mask));
                checkIsPaymasterSignatureValid(op, false);
                op.paymasterAndData[byteIndex] = bytes1(uint8(op.paymasterAndData[byteIndex]) ^ uint8(mask));
            }
        }
    }

    function checkIsPaymasterSignatureValid(UserOperation memory op, bool isSignatureValid) internal {
        bytes32 opHash = getOpHash(op);
        vm.prank(address(entryPoint));
        (, uint256 validationData) = paymaster.validatePaymasterUserOp(op, opHash, 0);
        assertEq(uint160(validationData), isSignatureValid ? 0 : 1);
    }

    function getSignedPaymasterData(
        uint8 mode,
        bool allowAllBundlers,
        UserOperation memory userOp
    )
        private
        view
        returns (bytes memory)
    {
        PaymasterData memory data = PaymasterData({
            paymasterAddress: address(paymaster),
            validUntil: 0,
            validAfter: 0,
            allowAllBundlers: allowAllBundlers
        });

        if (mode == VERIFYING_MODE) {
            return getVerifyingModeData(data, userOp, paymasterSignerKey);
        } else if (mode == ERC20_MODE) {
            return getERC20ModeData(
                data, address(token), POSTOP_GAS, EXCHANGE_RATE, uint128(0), userOp, paymasterSignerKey
            );
        }

        revert("UNEXPECTED MODE");
    }

    function getVerifyingModeData(
        PaymasterData memory data,
        UserOperation memory userOp,
        uint256 signerKey
    )
        private
        view
        returns (bytes memory)
    {
        // set paymasterAndData here so that correct hash is calculated.
        userOp.paymasterAndData = abi.encodePacked(
            address(paymaster), VERIFYING_MODE, data.allowAllBundlers, data.validUntil, data.validAfter
        );
        bytes32 hash = paymaster.getHash(VERIFYING_MODE, userOp);
        bytes memory sig = getSignature(hash, signerKey);

        return abi.encodePacked(
            data.paymasterAddress, VERIFYING_MODE, data.allowAllBundlers, data.validUntil, data.validAfter, sig
        );
    }

    function getERC20ModeData(
        PaymasterData memory data,
        address erc20,
        uint128 postOpGas,
        uint256 exchangeRate,
        uint128 paymasterValidationGasLimit,
        UserOperation memory userOp,
        uint256 signerKey
    )
        private
        view
        returns (bytes memory)
    {
        userOp.paymasterAndData = abi.encodePacked(
            data.paymasterAddress,
            ERC20_MODE,
            data.allowAllBundlers,
            data.validUntil,
            data.validAfter,
            erc20,
            postOpGas,
            exchangeRate,
            paymasterValidationGasLimit,
            treasury
        );
        bytes32 hash = paymaster.getHash(ERC20_MODE, userOp);
        bytes memory sig = getSignature(hash, signerKey);

        return abi.encodePacked(
            data.paymasterAddress,
            ERC20_MODE,
            data.allowAllBundlers,
            data.validUntil,
            data.validAfter,
            erc20,
            postOpGas,
            exchangeRate,
            paymasterValidationGasLimit,
            treasury,
            sig
        );
    }

    function getSignature(bytes32 hash, uint256 signingKey) private pure returns (bytes memory) {
        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(hash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signingKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function fillUserOp() internal view returns (UserOperation memory op) {
        op.sender = address(account);
        op.nonce = entryPoint.getNonce(address(account), 0);
        op.callData = abi.encodeWithSelector(
            SimpleAccount.execute.selector, address(counter), 0, abi.encodeWithSelector(TestCounter.count.selector)
        );
        op.callGasLimit = 50_000;
        op.verificationGasLimit = 180_000;
        op.preVerificationGas = 50_000;
        op.maxFeePerGas = 50;
        op.maxPriorityFeePerGas = 15;
        op.signature = signUserOp(op, userKey);
        return op;
    }

    function getOpHash(UserOperation memory op) internal view returns (bytes32) {
        return entryPoint.getUserOpHash(op);
    }

    function signUserOp(UserOperation memory op, uint256 _key) public view returns (bytes memory signature) {
        bytes32 hash = entryPoint.getUserOpHash(op);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_key, hash.toEthSignedMessageHash());
        signature = abi.encodePacked(r, s, v);
    }

    function submitUserOp(UserOperation memory op) private {
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);
    }

    function setupERC20Environment() private {
        token.sudoMint(address(account), 1000e18);
        token.sudoApprove(address(account), address(paymaster), UINT256_MAX);
    }
}
