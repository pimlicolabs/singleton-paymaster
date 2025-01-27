// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { Test, console } from "forge-std/Test.sol";
import { MessageHashUtils } from "openzeppelin-contracts-v5.0.2/contracts/utils/cryptography/MessageHashUtils.sol";
import { IERC20 } from "openzeppelin-contracts-v5.0.2/contracts/token/ERC20/IERC20.sol";

import { IEntryPoint } from "@account-abstraction-v7/interfaces/IEntryPoint.sol";
import { PackedUserOperation } from "account-abstraction-v7/interfaces/PackedUserOperation.sol";
import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";

import { ERC20PostOpContext, BaseSingletonPaymaster } from "../src/base/BaseSingletonPaymaster.sol";
import { SingletonPaymasterV7 } from "../src/SingletonPaymasterV7.sol";
import { PostOpMode } from "../src/interfaces/PostOpMode.sol";

import { SimpleAccountFactory, SimpleAccount } from "./utils/account-abstraction/v07/samples/SimpleAccountFactory.sol";
import { EntryPoint } from "./utils/account-abstraction/v07/core/EntryPoint.sol";
import { TestERC20 } from "./utils/TestERC20.sol";
import { TestCounter } from "./utils/TestCounter.sol";

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
    uint8 allowAllBundlers;
}

contract SingletonPaymasterV7Test is Test {
    // helpers
    uint8 immutable VERIFYING_MODE = 0;
    uint8 immutable ERC20_MODE = 1;
    uint8 immutable ERC20_WITH_CONSTANT_FEE_MODE = 2;
    uint8 immutable ALLOW_ALL_BUNDLERS = 1;
    uint8 immutable ALLOW_WHITELISTED_BUNDLERS = 0;
    uint256 immutable EXCHANGE_RATE = 3000 * 1e18;
    uint128 immutable POSTOP_GAS = 50_000;
    uint128 immutable PAYMASTER_VALIDATION_GAS_LIMIT = 30_000;
    /// @notice The length of the ERC-20 config without singature.
    uint8 immutable ERC20_PAYMASTER_DATA_LENGTH = 118; // 116 + 2 (mode & allowAllBundlers)

    /// @notice The length of the ERC-20 with constant fee config with singature.
    uint8 immutable ERC20_WITH_CONSTANT_FEE_PAYMASTER_DATA_LENGTH = 150; // 116 + 32 (constantFee) + 2 (mode &
        // allowAllBundlers)

    /// @notice The length of the verfiying config without singature.
    uint8 immutable VERIFYING_PAYMASTER_DATA_LENGTH = 14; // 12 + 2 (mode & allowAllBundlers)

    address payable beneficiary;
    address paymasterOwner;
    address paymasterSigner;
    address treasury;
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
        treasury = makeAddr("treasury");
        (paymasterSigner, paymasterSignerKey) = makeAddrAndKey("paymasterSigner");
        (, unauthorizedSignerKey) = makeAddrAndKey("unauthorizedSigner");
        (user, userKey) = makeAddrAndKey("user");

        entryPoint = new EntryPoint();
        accountFactory = new SimpleAccountFactory(entryPoint);
        account = accountFactory.createAccount(user, 0);

        paymaster = new SingletonPaymasterV7(address(entryPoint), paymasterOwner, new address[](0));
        paymaster.deposit{ value: 100e18 }();

        vm.prank(paymasterOwner);
        paymaster.addSigner(paymasterSigner);
    }

    function testDeployment() external {
        SingletonPaymasterV7 subject = new SingletonPaymasterV7(address(entryPoint), paymasterOwner, new address[](0));
        vm.prank(paymasterOwner);
        subject.addSigner(paymasterSigner);

        assertEq(subject.owner(), paymasterOwner);
        // assertEq(subject.treasury(), paymasterOwner);
        assertTrue(subject.signers(paymasterSigner));
    }

    function testERC20Success() external {
        setupERC20Environment();

        // treasury should have no tokens
        assertEq(token.balanceOf(treasury), 0);

        PackedUserOperation memory op = fillUserOp();
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

    function testERC20WithConstantFeeSuccess() external {
        setupERC20Environment();

        // treasury should have no tokens
        assertEq(token.balanceOf(treasury), 0);

        PackedUserOperation memory op = fillUserOp();
        op.paymasterAndData = getSignedPaymasterData(ERC20_WITH_CONSTANT_FEE_MODE, ALLOW_ALL_BUNDLERS, op);
        op.signature = signUserOp(op, userKey);

        // check that UserOperationSponsored log is emitted.
        // event data check is skipped because we don't know how much will be spent.
        vm.expectEmit(true, true, true, false, address(paymaster));
        emit BaseSingletonPaymaster.UserOperationSponsored(
            getOpHash(op), op.sender, ERC20_WITH_CONSTANT_FEE_MODE, address(token), 0, EXCHANGE_RATE
        );

        submitUserOp(op);

        // treasury should now have tokens
        assertGt(token.balanceOf(treasury), 0);
    }

    function testVerifyingSuccess() external {
        PackedUserOperation memory op = fillUserOp();
        op.paymasterAndData = getSignedPaymasterData(VERIFYING_MODE, ALLOW_ALL_BUNDLERS, op);
        op.signature = signUserOp(op, userKey);

        // check that UserOperationSponsored log is emitted.
        vm.expectEmit(address(paymaster));
        emit BaseSingletonPaymaster.UserOperationSponsored(getOpHash(op), op.sender, VERIFYING_MODE, address(0), 0, 0);

        submitUserOp(op);
    }

    function test_RevertWhen_ERC20PaymasterSignatureInvalid(uint8 _mode) external {
        uint8 mode = uint8(bound(_mode, 1, 2));

        PackedUserOperation memory op = fillUserOp();

        // sign with random private key to force false signature

        PaymasterData memory data = PaymasterData(address(paymaster), 50_000, 100_000, 0, 0, ALLOW_ALL_BUNDLERS);
        op.paymasterAndData = getERC20ModeData(
            mode,
            data,
            address(token),
            POSTOP_GAS,
            EXCHANGE_RATE,
            PAYMASTER_VALIDATION_GAS_LIMIT,
            op,
            unauthorizedSignerKey
        );
        op.signature = signUserOp(op, userKey);

        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, uint256(0), "AA34 signature error"));
        submitUserOp(op);
    }

    function test_RevertWhen_VerifyingPaymasterSignatureInvalid() external {
        PackedUserOperation memory op = fillUserOp();

        PaymasterData memory data = PaymasterData(address(paymaster), 50_000, 100_000, 0, 0, ALLOW_ALL_BUNDLERS);
        op.paymasterAndData = getVerifyingModeData(data, op, unauthorizedSignerKey);
        op.signature = signUserOp(op, userKey);

        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, uint256(0), "AA34 signature error"));
        submitUserOp(op);
    }

    function test_RevertWhen_PaymasterModeInvalid(uint8 _invalidMode) external {
        vm.assume(
            _invalidMode != ERC20_MODE && _invalidMode != VERIFYING_MODE && _invalidMode != ERC20_WITH_CONSTANT_FEE_MODE
        );

        PackedUserOperation memory op = fillUserOp();

        op.paymasterAndData =
            abi.encodePacked(address(paymaster), uint128(100_000), uint128(50_000), _invalidMode, ALLOW_ALL_BUNDLERS);
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
        uint8 mode = uint8(bound(_mode, 0, 2));
        setupERC20Environment();

        if (mode == VERIFYING_MODE) {
            vm.assume(_randomBytes.length < 12);
        }

        if (mode == ERC20_MODE) {
            vm.assume(_randomBytes.length < ERC20_PAYMASTER_DATA_LENGTH - 2);
        }

        if (mode == ERC20_WITH_CONSTANT_FEE_MODE) {
            vm.assume(_randomBytes.length < ERC20_WITH_CONSTANT_FEE_PAYMASTER_DATA_LENGTH - 2);
        }

        PackedUserOperation memory op = fillUserOp();

        op.paymasterAndData = abi.encodePacked(
            address(paymaster), uint128(100_000), uint128(50_000), mode, ALLOW_ALL_BUNDLERS, _randomBytes
        );
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
        uint8 mode = uint8(bound(_mode, 0, 2));
        setupERC20Environment();

        PackedUserOperation memory op = fillUserOp();

        if (mode == VERIFYING_MODE) {
            op.paymasterAndData = abi.encodePacked(
                address(paymaster), // paymaster
                uint128(100_000), // paymaster verification gas
                uint128(50_000), // paymaster postop gas
                mode, // mode
                ALLOW_ALL_BUNDLERS,
                uint48(0), // validUntil
                uint48(0), // validAfter
                "BYTES WITH INVALID SIGNATURE LENGTH"
            );
        }

        if (mode == ERC20_MODE) {
            op.paymasterAndData = abi.encodePacked(
                address(paymaster), // paymaster
                uint128(100_000), // paymaster verification gas
                uint128(50_000), // paymaster postop gas
                mode, // mode
                ALLOW_ALL_BUNDLERS,
                uint48(0), // validUntil
                int48(0), // validAfter
                address(token), // token
                uint128(1), // postOpGas
                uint256(1), // exchangeRate
                uint128(0), // paymasterValidationGasLimit
                treasury, // treasury
                "BYTES WITH INVALID SIGNATURE LENGTH"
            );
        }

        if (mode == ERC20_WITH_CONSTANT_FEE_MODE) {
            op.paymasterAndData = abi.encodePacked(
                address(paymaster), // paymaster
                uint128(100_000), // paymaster verification gas
                uint128(50_000), // paymaster postop gas
                mode, // mode
                ALLOW_ALL_BUNDLERS,
                uint48(0), // validUntil
                int48(0), // validAfter
                address(token), // token
                uint128(1), // postOpGas
                uint256(1), // exchangeRate
                uint128(0), // paymasterValidationGasLimit
                treasury // treasury
            );

            op.paymasterAndData =
                abi.encodePacked(op.paymasterAndData, uint256(1), "BYTES WITH INVALID SIGNATURE LENGTH"); // constantFee
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

    function test_RevertWhen_TokenAddressInvalid(uint8 _mode) external {
        uint8 mode = uint8(bound(_mode, 1, 2));
        setupERC20Environment();

        PackedUserOperation memory op = fillUserOp();

        if (mode == ERC20_MODE) {
            op.paymasterAndData = abi.encodePacked(
                address(paymaster), // paymaster
                uint128(100_000), // paymaster verification gas
                uint128(50_000), // paymaster postop gas
                mode, // mode
                ALLOW_ALL_BUNDLERS,
                uint48(0), // validUntil
                int48(0), // validAfter
                address(0), // token will throw here, token address cannot be zero
                uint128(1), // postOpGas
                uint256(1), // exchangeRate
                uint128(0), // paymasterValidationGasLimit
                treasury, // treasury
                "BYTES WITH INVALID SIGNATURE LENGTH"
            );
        }

        if (mode == ERC20_WITH_CONSTANT_FEE_MODE) {
            op.paymasterAndData = abi.encodePacked(
                address(paymaster), // paymaster
                uint128(100_000), // paymaster verification gas
                uint128(50_000), // paymaster postop gas
                mode, // mode
                ALLOW_ALL_BUNDLERS,
                uint48(0), // validUntil
                int48(0), // validAfter
                address(0), // token will throw here, token address cannot be zero
                uint128(1), // postOpGas
                uint256(1), // exchangeRate
                uint128(0), // paymasterValidationGasLimit
                treasury // treasury
            );

            op.paymasterAndData =
                abi.encodePacked(op.paymasterAndData, uint256(1), "BYTES WITH INVALID SIGNATURE LENGTH"); // constantFee
        }

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

    function test_RevertWhen_ExchangeRateInvalid(uint8 _mode) external {
        uint8 mode = uint8(bound(_mode, 1, 2));
        setupERC20Environment();

        PackedUserOperation memory op = fillUserOp();

        if (mode == ERC20_MODE) {
            op.paymasterAndData = abi.encodePacked(
                address(paymaster), // paymaster
                uint128(100_000), // paymaster verification gas
                uint128(50_000), // paymaster postop gas
                mode, // mode
                ALLOW_ALL_BUNDLERS,
                uint48(0), // validUntil
                int48(0), // validAfter
                address(token), // token
                uint128(1), // postOpGas
                uint256(0), // exchangeRate will throw here, price cannot be zero
                uint128(0), // paymasterValidationGasLimit
                treasury, // treasury
                "BYTES WITH INVALID SIGNATURE LENGTH"
            );
        }

        if (mode == ERC20_WITH_CONSTANT_FEE_MODE) {
            op.paymasterAndData = abi.encodePacked(
                address(paymaster), // paymaster
                uint128(100_000), // paymaster verification gas
                uint128(50_000), // paymaster postop gas
                mode, // mode
                ALLOW_ALL_BUNDLERS,
                uint48(0), // validUntil
                int48(0), // validAfter
                address(token), // token
                uint128(1), // postOpGas
                uint256(0), // exchangeRate will throw here, price cannot be zero
                uint128(0), // paymasterValidationGasLimit
                treasury // treasury
            );

            op.paymasterAndData =
                abi.encodePacked(op.paymasterAndData, uint256(1), "BYTES WITH INVALID SIGNATURE LENGTH"); // constantFee
        }

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

        op.paymasterAndData = abi.encodePacked(address(paymaster), uint128(100_000), uint128(50_000));

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

    function test_RevertWhen_PostOpTransferFromFailed(uint8 _mode) external {
        uint8 mode = uint8(bound(_mode, 1, 2));

        PackedUserOperation memory op = fillUserOp();

        op.paymasterAndData = getSignedPaymasterData(mode, ALLOW_ALL_BUNDLERS, op);
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
        uint256 _actualUserOpFeePerGas,
        uint256 _constantFee,
        uint8 _mode
    )
        external
    {
        token.sudoMint(address(account), 1e50);
        token.sudoApprove(address(account), address(paymaster), UINT256_MAX);

        uint8 mode = uint8(bound(_mode, 1, 2));
        uint128 postOpGas = uint128(bound(_postOpGas, 21_000, 250_000));
        uint256 actualUserOpFeePerGas = bound(_actualUserOpFeePerGas, 0.01 gwei, 5000 gwei);
        uint256 userOperationGasUsed = bound(_userOperationGasUsed, 21_000, 30_000_000);
        uint256 exchangeRate = bound(_exchangeRate, 1e6, 1e20);
        uint256 constantFee = bound(_constantFee, 0, 1000);

        uint256 actualGasCost = userOperationGasUsed * actualUserOpFeePerGas;

        bytes memory context = abi.encode(
            ERC20PostOpContext({
                sender: address(account),
                token: address(token),
                treasury: address(treasury),
                exchangeRate: exchangeRate,
                postOpGas: postOpGas,
                userOpHash: 0x0000000000000000000000000000000000000000000000000000000000000000,
                maxFeePerGas: 0,
                maxPriorityFeePerGas: 0,
                preOpGasApproximation: uint256(0),
                executionGasLimit: uint256(0),
                constantFee: mode == ERC20_WITH_CONSTANT_FEE_MODE ? constantFee : uint256(0)
            })
        );

        uint256 expectedCostInTokenWithoutConstantFee =
            paymaster.getCostInToken(actualGasCost, postOpGas, actualUserOpFeePerGas, exchangeRate);

        uint256 expectedCostInToken = mode == ERC20_WITH_CONSTANT_FEE_MODE
            ? expectedCostInTokenWithoutConstantFee + constantFee
            : expectedCostInTokenWithoutConstantFee;

        vm.prank(address(entryPoint));
        paymaster.postOp(PostOpMode.opSucceeded, context, actualGasCost, actualUserOpFeePerGas);

        // TODO: Check when preOpGasApproximation is not 0
        vm.assertEq(expectedCostInToken, token.balanceOf(treasury));
    }

    function test_postOpCalculation_withPenalty(
        uint256 _exchangeRate,
        uint128 _postOpGas,
        uint256 _userOperationGasUsed,
        uint256 _actualUserOpFeePerGas,
        uint256 _constantFee,
        uint8 _mode
    )
        external
    {
        token.sudoMint(address(account), 1e50);
        token.sudoApprove(address(account), address(paymaster), UINT256_MAX);

        uint8 mode = uint8(bound(_mode, 1, 2));
        uint128 postOpGas = uint128(bound(_postOpGas, 21_000, 250_000));
        uint256 actualUserOpFeePerGas = bound(_actualUserOpFeePerGas, 0.01 gwei, 5000 gwei);
        uint256 userOperationGasUsed = bound(_userOperationGasUsed, 21_000, 30_000_000);
        uint256 exchangeRate = bound(_exchangeRate, 1e6, 1e20);
        uint256 constantFee = bound(_constantFee, 0, 1000);

        uint256 actualGasCost = userOperationGasUsed * actualUserOpFeePerGas;
        uint256 preOpGasApproximation = uint256(0);
        uint256 executionGasLimit = uint256(userOperationGasUsed * 2);

        bytes memory context = abi.encode(
            ERC20PostOpContext({
                sender: address(account),
                token: address(token),
                treasury: address(treasury),
                exchangeRate: exchangeRate,
                postOpGas: postOpGas,
                userOpHash: 0x0000000000000000000000000000000000000000000000000000000000000000,
                maxFeePerGas: 0,
                maxPriorityFeePerGas: 0,
                preOpGasApproximation: preOpGasApproximation,
                executionGasLimit: executionGasLimit,
                constantFee: mode == ERC20_WITH_CONSTANT_FEE_MODE ? constantFee : uint256(0)
            })
        );

        vm.prank(address(entryPoint));
        paymaster.postOp(PostOpMode.opSucceeded, context, actualGasCost, actualUserOpFeePerGas);

        uint256 expectedPenaltyGasCost = paymaster._expectedPenaltyGasCost(
            actualGasCost, actualUserOpFeePerGas, postOpGas, preOpGasApproximation, executionGasLimit
        );

        uint256 expectedCostInTokenWithoutConstantFee = paymaster.getCostInToken(
            actualGasCost + expectedPenaltyGasCost, postOpGas, actualUserOpFeePerGas, exchangeRate
        );

        uint256 expectedCostInToken = mode == ERC20_WITH_CONSTANT_FEE_MODE
            ? expectedCostInTokenWithoutConstantFee + constantFee
            : expectedCostInTokenWithoutConstantFee;

        vm.assertEq(expectedCostInToken, token.balanceOf(treasury));
    }

    function test_RevertWhen_BundlerNotAllowed() external {
        setupERC20Environment();

        // treasury should have no tokens
        assertEq(token.balanceOf(treasury), 0);

        PackedUserOperation memory op = fillUserOp();
        op.paymasterAndData = getSignedPaymasterData(ERC20_MODE, ALLOW_WHITELISTED_BUNDLERS, op);
        op.signature = signUserOp(op, userKey);

        // check that UserOperationSponsored log is emitted.
        // event data check is skipped because we don't know how much will be spent.
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                uint256(0),
                "AA33 reverted",
                abi.encodeWithSelector(BaseSingletonPaymaster.BundlerNotAllowed.selector, address(DEFAULT_SENDER))
            )
        );

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

        PackedUserOperation memory op = fillUserOp();
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
    )
        external
    {
        PackedUserOperation memory op = fillUserOp();
        PaymasterData memory data = PaymasterData(
            address(paymaster),
            _paymasterVerificationGas,
            _paymasterPostOpGas,
            _validUntil,
            _validAfter,
            ALLOW_ALL_BUNDLERS
        );

        op.paymasterAndData = getVerifyingModeData(data, op, paymasterSignerKey);
        op.signature = signUserOp(op, userKey);
        bytes32 opHash = getOpHash(op);

        vm.prank(address(entryPoint));
        (bytes memory context, uint256 validationData) = paymaster.validatePaymasterUserOp(op, opHash, 0);
        vm.assertEq(uint160(validationData), 0);
        vm.assertEq(context, "", "context should always be empty when used in verifying mode");
    }

    // context and validation data should be properly encoded in Verifying mode.
    // should not revert when a invalid signature is presented (requirement by entryPoint so that bundler can run
    // simulations)
    function test_verifyingValidatePaymasterUserOp(uint48 _validUntil, uint48 _validAfter) external {
        PackedUserOperation memory op = fillUserOp();
        PaymasterData memory data =
            PaymasterData(address(paymaster), 50_000, 100_000, _validUntil, _validAfter, ALLOW_ALL_BUNDLERS);

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
        uint256 _exchangeRate,
        uint8 _mode
    )
        external
    {
        uint8 mode = uint8(bound(_mode, 1, 2));
        vm.assume(_exchangeRate > 0);
        vm.assume(_token != address(0));

        PackedUserOperation memory op = fillUserOp();
        PaymasterData memory data =
            PaymasterData(address(paymaster), 50_000, 100_000, _validUntil, _validAfter, ALLOW_ALL_BUNDLERS);

        // Test with correct signature
        validateERC20PaymasterUserOp(mode, op, data, _token, _postOpGas, _exchangeRate, 0, paymasterSignerKey);

        // Test with incorrect signature
        validateERC20PaymasterUserOp(mode, op, data, _token, _postOpGas, _exchangeRate, 1, unauthorizedSignerKey);
    }

    function validateERC20PaymasterUserOp(
        uint8 mode,
        PackedUserOperation memory op,
        PaymasterData memory data,
        address tokenAddress,
        uint128 postOpGas,
        uint256 exchangeRate,
        uint160 expectedSignature,
        uint256 signerKey
    )
        internal
    {
        op.paymasterAndData = getERC20ModeData(
            mode, data, tokenAddress, postOpGas, exchangeRate, PAYMASTER_VALIDATION_GAS_LIMIT, op, signerKey
        );
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
        flipUserOperationBitsAndValidateSignature(ERC20_WITH_CONSTANT_FEE_MODE);
        flipUserOperationBitsAndValidateSignature(VERIFYING_MODE);
    }

    // HELPERS //

    function flipUserOperationBitsAndValidateSignature(uint8 _mode) internal {
        PackedUserOperation memory op = fillUserOp();
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

        uint256 paymasterConfigLength = 52;

        if (_mode == ERC20_MODE) {
            paymasterConfigLength += ERC20_PAYMASTER_DATA_LENGTH;
        }

        if (_mode == ERC20_WITH_CONSTANT_FEE_MODE) {
            paymasterConfigLength += ERC20_WITH_CONSTANT_FEE_PAYMASTER_DATA_LENGTH;
        }

        if (_mode == VERIFYING_MODE) {
            paymasterConfigLength += VERIFYING_PAYMASTER_DATA_LENGTH;
        }

        // check paymasterAndData
        for (uint256 byteIndex = 0; byteIndex < paymasterConfigLength; byteIndex++) {
            for (uint8 bitPosition = 0; bitPosition < 8; bitPosition++) {
                uint256 mask = 1 << bitPosition;

                // we don't want to flip the mode byte and allowAllBundlers byte
                if (byteIndex == 52 || byteIndex == 53) {
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

    function getSignedPaymasterData(
        uint8 mode,
        uint8 allowAllBundlers,
        PackedUserOperation memory userOp
    )
        private
        view
        returns (bytes memory)
    {
        PaymasterData memory data = PaymasterData({
            paymasterAddress: address(paymaster),
            preVerificationGas: 100_000,
            postOpGas: 50_000,
            validUntil: 0,
            validAfter: 0,
            allowAllBundlers: allowAllBundlers
        });

        if (mode == VERIFYING_MODE) {
            return getVerifyingModeData(data, userOp, paymasterSignerKey);
        } else if (mode == ERC20_MODE || mode == ERC20_WITH_CONSTANT_FEE_MODE) {
            return getERC20ModeData(
                mode,
                data,
                address(token),
                POSTOP_GAS,
                EXCHANGE_RATE,
                PAYMASTER_VALIDATION_GAS_LIMIT,
                userOp,
                paymasterSignerKey
            );
        }

        revert("unexpected mode");
    }

    function getVerifyingModeData(
        PaymasterData memory data,
        PackedUserOperation memory userOp,
        uint256 signerKey
    )
        private
        view
        returns (bytes memory)
    {
        userOp.paymasterAndData = abi.encodePacked(
            data.paymasterAddress,
            data.preVerificationGas,
            data.postOpGas,
            VERIFYING_MODE,
            data.allowAllBundlers,
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
            data.allowAllBundlers,
            data.validUntil,
            data.validAfter,
            sig
        );
    }

    function getERC20ModeData(
        uint8 mode,
        PaymasterData memory data,
        address erc20,
        uint128 postOpGas,
        uint256 exchangeRate,
        uint128 paymasterValidationGasLimit,
        PackedUserOperation memory userOp,
        uint256 signingKey
    )
        private
        view
        returns (bytes memory)
    {
        userOp.paymasterAndData = abi.encodePacked(
            data.paymasterAddress,
            data.preVerificationGas,
            data.postOpGas,
            mode,
            data.allowAllBundlers,
            data.validUntil,
            data.validAfter,
            erc20,
            postOpGas,
            exchangeRate,
            paymasterValidationGasLimit
        );

        if (mode == ERC20_WITH_CONSTANT_FEE_MODE) {
            uint256 constantFee = 1;
            userOp.paymasterAndData = abi.encodePacked(userOp.paymasterAndData, treasury, constantFee);
        } else {
            userOp.paymasterAndData = abi.encodePacked(userOp.paymasterAndData, treasury);
        }

        bytes32 hash = paymaster.getHash(mode, userOp);
        bytes memory sig = getSignature(hash, signingKey);

        userOp.paymasterAndData = abi.encodePacked(userOp.paymasterAndData, sig);

        return userOp.paymasterAndData;
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
        op.accountGasLimits = bytes32(abi.encodePacked(bytes16(uint128(80_000)), bytes16(uint128(50_000))));
        op.preVerificationGas = 50_000;
        op.gasFees = bytes32(abi.encodePacked(bytes16(uint128(100)), bytes16(uint128(1_000_000_000))));
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
