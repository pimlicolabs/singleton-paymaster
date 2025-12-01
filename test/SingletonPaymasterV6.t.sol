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

import "forge-std/console.sol";

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
    uint8 allowAllBundlers;
}

contract SingletonPaymasterV6Test is Test {
    uint8 immutable VERIFYING_MODE = 0;
    uint8 immutable ERC20_MODE = 1;
    uint8 immutable ALLOW_ALL_BUNDLERS = 1;
    uint8 immutable ALLOW_WHITELISTED_BUNDLERS = 0;
    uint256 immutable EXCHANGE_RATE = 3000 * 1e18;
    uint128 immutable POSTOP_GAS = 50_000;
    /// @notice The length of the ERC-20 config without singature.
    uint8 immutable ERC20_PAYMASTER_DATA_LENGTH = 117;

    /// @notice The length of the verfiying config without singature.
    uint8 immutable VERIFYING_PAYMASTER_DATA_LENGTH = 12; // 12 (mode & allowAllBundlers)

    address payable beneficiary;
    address paymasterOwner;
    address paymasterSigner;
    address treasury;
    address manager;
    address recipient;
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
        recipient = makeAddr("recipient");
        manager = makeAddr("manager");
        (paymasterSigner, paymasterSignerKey) = makeAddrAndKey("paymasterSigner");
        (, unauthorizedSignerKey) = makeAddrAndKey("unauthorizedSigner");
        (user, userKey) = makeAddrAndKey("user");

        entryPoint = new EntryPoint();
        accountFactory = new SimpleAccountFactory(entryPoint);
        account = accountFactory.createAccount(user, 0);

        paymaster = new SingletonPaymasterV6(address(entryPoint), paymasterOwner, manager, new address[](0));
        paymaster.deposit{ value: 100e18 }();

        vm.prank(paymasterOwner);
        paymaster.addSigner(paymasterSigner);
    }

    function test_Deployment() external {
        SingletonPaymasterV6 subject =
            new SingletonPaymasterV6(address(entryPoint), paymasterOwner, manager, new address[](0));
        vm.prank(paymasterOwner);
        subject.addSigner(paymasterSigner);

        assertTrue(subject.hasRole(paymaster.DEFAULT_ADMIN_ROLE(), paymasterOwner));
        assertTrue(subject.signers(paymasterSigner));
    }

    function test_ERC20Success() external {
        setupERC20Environment(UINT256_MAX);

        // treasury should have no tokens
        assertEq(token.balanceOf(treasury), 0);

        UserOperation memory op = fillUserOp();
        op.paymasterAndData = getSignedPaymasterData(ERC20_MODE, ALLOW_ALL_BUNDLERS, op, uint8(0), uint8(0), uint8(0));
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

    function test_ERC20WithConstantFeeSuccess() external {
        setupERC20Environment(UINT256_MAX);

        // treasury should have no tokens
        assertEq(token.balanceOf(treasury), 0);

        UserOperation memory op = fillUserOp();
        op.paymasterAndData = getSignedPaymasterData(ERC20_MODE, ALLOW_ALL_BUNDLERS, op, uint8(1), uint8(0), uint8(0));
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

    function test_VerifyingSuccess() external {
        UserOperation memory op = fillUserOp();
        op.paymasterAndData =
            getSignedPaymasterData(VERIFYING_MODE, ALLOW_ALL_BUNDLERS, op, uint8(0), uint8(0), uint8(0));
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
        op.paymasterAndData = getERC20ModeData(
            data,
            address(token),
            POSTOP_GAS,
            EXCHANGE_RATE,
            uint128(0),
            op,
            unauthorizedSignerKey,
            uint8(0),
            uint8(0),
            uint8(0)
        );
        op.signature = signUserOp(op, userKey);

        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, uint256(0), "AA34 signature error"));
        submitUserOp(op);
    }

    function test_RevertWhen_ERC20WithConstantFeePaymasterSignatureInvalid() external {
        UserOperation memory op = fillUserOp();

        // sign with random private key to force false signature
        PaymasterData memory data = PaymasterData(address(paymaster), 0, 0, ALLOW_ALL_BUNDLERS);
        op.paymasterAndData = getERC20ModeData(
            data,
            address(token),
            POSTOP_GAS,
            EXCHANGE_RATE,
            uint128(0),
            op,
            unauthorizedSignerKey,
            uint8(1),
            uint8(0),
            uint8(0)
        );
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

    function test_ERC20LegacySuccess() external {
        setupERC20Environment(UINT256_MAX);

        // on chains that don't support EIP-1559, the UserOperation's maxFee & maxPriorityFee are equal.
        UserOperation memory op = fillUserOp();
        op.maxPriorityFeePerGas = 5;
        op.maxFeePerGas = 5;
        op.paymasterAndData = getSignedPaymasterData(ERC20_MODE, ALLOW_ALL_BUNDLERS, op, uint8(0), uint8(0), uint8(0));
        op.signature = signUserOp(op, userKey);

        // check that UserOperationSponsored log is emitted.
        // event data check is skipped because we don't know how much will be spent.
        vm.expectEmit(true, true, true, false, address(paymaster));
        emit BaseSingletonPaymaster.UserOperationSponsored(
            getOpHash(op), op.sender, ERC20_MODE, address(token), 0, EXCHANGE_RATE
        );

        submitUserOp(op);
    }

    function test_ERC20WithConstantFeeLegacySuccess() external {
        setupERC20Environment(UINT256_MAX);

        // on chains that don't support EIP-1559, the UserOperation's maxFee & maxPriorityFee are equal.
        UserOperation memory op = fillUserOp();
        op.maxPriorityFeePerGas = 5;
        op.maxFeePerGas = 5;
        op.paymasterAndData = getSignedPaymasterData(ERC20_MODE, ALLOW_ALL_BUNDLERS, op, uint8(1), uint8(0), uint8(0));
        op.signature = signUserOp(op, userKey);

        // check that UserOperationSponsored log is emitted.
        // event data check is skipped because we don't know how much will be spent.
        vm.expectEmit(true, true, true, false, address(paymaster));
        emit BaseSingletonPaymaster.UserOperationSponsored(
            getOpHash(op), op.sender, ERC20_MODE, address(token), 0, EXCHANGE_RATE
        );

        submitUserOp(op);
    }

    function test_ERC20WithPrefund() external {
        setupERC20Environment(UINT256_MAX);

        // on chains that don't support EIP-1559, the UserOperation's maxFee & maxPriorityFee are equal.
        UserOperation memory op = fillUserOp();
        op.maxPriorityFeePerGas = 5;
        op.maxFeePerGas = 5;
        op.paymasterAndData =
            getSignedPaymasterData(ERC20_MODE, ALLOW_ALL_BUNDLERS, op, uint8(0), uint8(0), uint128(1_000_000));
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

        op.paymasterAndData =
            abi.encodePacked(address(paymaster), uint8((ALLOW_ALL_BUNDLERS & 0x01) | (invalidMode << 1)));
        op.signature = signUserOp(op, userKey);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA33 reverted (or OOG)"));
        submitUserOp(op);
    }

    function test_RevertWhen_PaymasterConfigLengthInvalid(uint8 _mode, bytes calldata _randomBytes) external {
        uint8 mode = uint8(bound(_mode, 0, 1));
        setupERC20Environment(UINT256_MAX);

        if (mode == VERIFYING_MODE) {
            vm.assume(_randomBytes.length < 12);
        }

        if (mode == ERC20_MODE) {
            vm.assume(_randomBytes.length < ERC20_PAYMASTER_DATA_LENGTH);
        }

        UserOperation memory op = fillUserOp();

        op.paymasterAndData =
            abi.encodePacked(address(paymaster), uint8((ALLOW_ALL_BUNDLERS & 0x01) | (mode << 1)), _randomBytes);
        op.signature = signUserOp(op, userKey);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, uint256(0), "AA33 reverted (or OOG)"));
        submitUserOp(op);
    }

    function test_RevertWhen_PaymasterSignatureLengthInvalid(
        uint8 _mode,
        uint8 _constantFeePresent,
        uint8 _recipientPresent,
        uint128 _preFundPresent
    )
        external
    {
        uint8 mode = uint8(bound(_mode, 0, 1));
        uint8 constantFeePresent = uint8(bound(_constantFeePresent, 0, 1));
        uint8 recipientPresent = uint8(bound(_recipientPresent, 0, 1));
        uint128 preFundPresent = uint128(bound(_preFundPresent, 0, 1));
        setupERC20Environment(UINT256_MAX);

        UserOperation memory op = fillUserOp();

        if (mode == VERIFYING_MODE) {
            op.paymasterAndData = abi.encodePacked(
                address(paymaster), // paymaster
                uint8((ALLOW_ALL_BUNDLERS & 0x01) | (mode << 1)),
                uint48(0), // validUntil
                int48(0), // validAfter
                "BYTES WITH INVALID SIGNATURE LENGTH"
            );
        }

        if (mode == ERC20_MODE) {
            op.paymasterAndData = abi.encodePacked(
                address(paymaster), // paymaster
                uint8((ALLOW_ALL_BUNDLERS & 0x01) | (mode << 1)),
                uint8(
                    (constantFeePresent == 1 ? 1 : 0) | (recipientPresent == 1 ? 1 << 1 : 0)
                        | (preFundPresent > 0 ? 1 << 2 : 0)
                ),
                uint48(0), // validUntil
                int48(0), // validAfter
                address(token), // token
                uint256(1), // postOpGas
                uint256(1), // exchangeRate
                uint128(0), // paymasterValidationGasLimit
                treasury // treasury
            );

            if (preFundPresent > 0) {
                op.paymasterAndData = abi.encodePacked(op.paymasterAndData, preFundPresent);
            }

            if (constantFeePresent == 1) {
                op.paymasterAndData = abi.encodePacked(
                    op.paymasterAndData,
                    uint128(1) // constantFee
                );
            }

            if (recipientPresent == 1) {
                op.paymasterAndData = abi.encodePacked(
                    op.paymasterAndData,
                    recipient // recipient
                );
            }

            op.paymasterAndData = abi.encodePacked(op.paymasterAndData, "BYTES WITH INVALID SIGNATURE LENGTH");
        }

        op.signature = signUserOp(op, userKey);
        vm.expectRevert(
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, uint256(0), string("AA33 reverted (or OOG)"))
        );
        submitUserOp(op);
    }

    // ERC20 mode specific errors

    function test_RevertWhen_PostOpTransferFromFailed(
        uint8 _constantFeePresent,
        uint8 _recipientPresent,
        uint128 _preFundPresent
    )
        external
    {
        uint8 constantFeePresent = uint8(bound(_constantFeePresent, 0, 1));
        uint8 recipientPresent = uint8(bound(_recipientPresent, 0, 1));
        uint128 preFundPresent = uint128(bound(_preFundPresent, 0, 1));

        UserOperation memory op = fillUserOp();

        op.paymasterAndData = getSignedPaymasterData(
            ERC20_MODE, ALLOW_ALL_BUNDLERS, op, constantFeePresent, recipientPresent, preFundPresent
        );
        op.signature = signUserOp(op, userKey);

        if (preFundPresent > 0) {
            vm.expectRevert(
                abi.encodeWithSelector(IEntryPoint.FailedOp.selector, uint256(0), string("AA33 reverted (or OOG)"))
            );
        } else {
            vm.expectRevert(
                abi.encodeWithSelector(IEntryPoint.FailedOp.selector, uint256(0), string("AA50 postOp revert"))
            );
        }
        submitUserOp(op);

        // check that treasury has no tokens
        assertEq(token.balanceOf(treasury), 0);
        if (recipientPresent == 1) {
            assertEq(token.balanceOf(recipient), 0);
        }
    }

    function test_RevertWhen_TokenAddressInvalid(
        uint8 _constantFeePresent,
        uint8 _recipientPresent,
        uint128 _preFundPresent
    )
        external
    {
        uint8 constantFeePresent = uint8(bound(_constantFeePresent, 0, 1));
        uint8 recipientPresent = uint8(bound(_recipientPresent, 0, 1));
        uint128 preFundPresent = uint128(bound(_preFundPresent, 0, 1));
        setupERC20Environment(UINT256_MAX);

        UserOperation memory op = fillUserOp();

        op.paymasterAndData = abi.encodePacked(
            address(paymaster), // paymaster
            uint8((ALLOW_ALL_BUNDLERS & 0x01) | (ERC20_MODE << 1)),
            uint8(
                (constantFeePresent == 1 ? 1 : 0) | (recipientPresent == 1 ? 1 << 1 : 0)
                    | (preFundPresent > 0 ? 1 << 2 : 0)
            ),
            uint48(0), // validUntil
            int48(0), // validAfter
            address(0), // **will throw here, token address cannot be zero.**
            uint128(1), // postOpGas
            uint256(1), // exchangeRate
            uint128(0), // paymasterValidationGasLimit
            treasury // treasury
        );

        if (preFundPresent > 0) {
            op.paymasterAndData = abi.encodePacked(op.paymasterAndData, preFundPresent);
        }

        if (constantFeePresent == 1) {
            op.paymasterAndData = abi.encodePacked(
                op.paymasterAndData,
                uint128(1) // constantFee
            );
        }

        if (recipientPresent == 1) {
            op.paymasterAndData = abi.encodePacked(
                op.paymasterAndData,
                recipient // recipient
            );
        }

        op.paymasterAndData = abi.encodePacked(op.paymasterAndData, "DummySignature");

        op.signature = signUserOp(op, userKey);
        vm.expectRevert(
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, uint256(0), string("AA33 reverted (or OOG)"))
        );
        submitUserOp(op);
    }

    function test_RevertWhen_ExchangeRateInvalid(
        uint8 _constantFeePresent,
        uint8 _recipientPresent,
        uint128 _preFundPresent
    )
        external
    {
        uint8 constantFeePresent = uint8(bound(_constantFeePresent, 0, 1));
        uint8 recipientPresent = uint8(bound(_recipientPresent, 0, 1));
        uint128 preFundPresent = uint128(bound(_preFundPresent, 0, 1));

        UserOperation memory op = fillUserOp();

        op.paymasterAndData = abi.encodePacked(
            address(paymaster), // paymaster
            uint8((ALLOW_ALL_BUNDLERS & 0x01) | (ERC20_MODE << 1)),
            uint8(
                (constantFeePresent == 1 ? 1 : 0) | (recipientPresent == 1 ? 1 << 1 : 0)
                    | (preFundPresent > 0 ? 1 << 2 : 0)
            ),
            uint48(0), // validUntil
            uint48(0), // validAfter
            address(token), // token
            uint128(0), // postOpGas
            uint256(0), // **will throw here, exchangeRate cannot be zero.**
            uint128(0), // paymasterValidationGasLimit
            treasury // treasury
        );

        if (preFundPresent > 0) {
            op.paymasterAndData = abi.encodePacked(op.paymasterAndData, preFundPresent);
        }

        if (constantFeePresent == 1) {
            op.paymasterAndData = abi.encodePacked(
                op.paymasterAndData,
                uint128(1) // constantFee
            );
        }

        if (recipientPresent == 1) {
            op.paymasterAndData = abi.encodePacked(
                op.paymasterAndData,
                recipient // recipient
            );
        }

        op.paymasterAndData = abi.encodePacked(op.paymasterAndData, "DummySignature");

        op.signature = signUserOp(op, userKey);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, uint256(0), "AA33 reverted (or OOG)"));
        submitUserOp(op);
    }

    function test_RevertWhen_PaymasterAndDataLengthInvalid() external {
        UserOperation memory op = fillUserOp();
        op.paymasterAndData = abi.encodePacked(address(paymaster));
        op.signature = signUserOp(op, userKey);

        vm.expectRevert();
        submitUserOp(op);

        test_RevertWhen_PaymasterAndDataLengthInvalid(uint8(0), uint8(1), uint128(0));
        test_RevertWhen_PaymasterAndDataLengthInvalid(uint8(1), uint8(0), uint128(0));
        test_RevertWhen_PaymasterAndDataLengthInvalid(uint8(1), uint8(1), uint128(0));

        test_RevertWhen_PaymasterAndDataLengthInvalid(uint8(0), uint8(1), uint128(1_000_000));
        test_RevertWhen_PaymasterAndDataLengthInvalid(uint8(1), uint8(0), uint128(1_000_000));
        test_RevertWhen_PaymasterAndDataLengthInvalid(uint8(1), uint8(1), uint128(1_000_000));
    }

    function test_RevertWhen_PaymasterAndDataLengthInvalid(
        uint8 constantFeePresent,
        uint8 recipientPresent,
        uint128 preFundPresent
    )
        internal
    {
        UserOperation memory op = fillUserOp();

        op.paymasterAndData = abi.encodePacked(
            address(paymaster), // paymaster
            uint8((ALLOW_ALL_BUNDLERS & 0x01) | (ERC20_MODE << 1)),
            uint8(
                (constantFeePresent == 1 ? 1 : 0) | (recipientPresent == 1 ? 1 << 1 : 0)
                    | (preFundPresent > 0 ? 1 << 2 : 0)
            ),
            uint48(0), // validUntil
            int48(0), // validAfter
            address(token), // token
            uint128(1), // postOpGas
            uint256(1) // exchangeRate
        );

        // split into 2 parts to avoid stack too deep
        op.paymasterAndData = abi.encodePacked(
            op.paymasterAndData,
            uint128(0), // paymasterValidationGasLimit
            treasury // treasury
        );

        // Skip adding constantFee so that the length is invalid
        // if (constantFeePresent == 1) {
        // op.paymasterAndData = abi.encodePacked(
        //     op.paymasterAndData,
        //     uint128(1) // constantFee
        // );
        // }

        // Skip adding recipient so that the length is invalid
        // if (recipientPresent == 1) {
        // op.paymasterAndData = abi.encodePacked(
        //     op.paymasterAndData,
        //     recipient // recipient
        // );
        // }

        // skip adding signature so that the length is invalid
        // op.paymasterAndData = abi.encodePacked(op.paymasterAndData, "DummySignature");

        op.signature = signUserOp(op, userKey);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, uint256(0), "AA33 reverted (or OOG)"));
        submitUserOp(op);
    }

    function test_RevertWhen_InvalidRecipient(uint8 _constantFeePresent, uint128 _preFundPresent) external {
        uint8 constantFeePresent = uint8(bound(_constantFeePresent, 0, 1));
        uint8 recipientPresent = 1;
        uint128 preFundPresent = uint128(bound(_preFundPresent, 0, 1));

        UserOperation memory op = fillUserOp();

        op.paymasterAndData = abi.encodePacked(
            address(paymaster), // paymaster
            uint8((ALLOW_ALL_BUNDLERS & 0x01) | (ERC20_MODE << 1)),
            uint8(
                (constantFeePresent == 1 ? 1 : 0) | (recipientPresent == 1 ? 1 << 1 : 0)
                    | (preFundPresent > 0 ? 1 << 2 : 0)
            ),
            uint48(0), // validUntil
            int48(0), // validAfter
            address(token), // token
            uint128(1), // postOpGas
            uint256(1) // exchangeRate
        );

        // split into 2 parts to avoid stack too deep
        op.paymasterAndData = abi.encodePacked(
            op.paymasterAndData,
            uint128(0), // paymasterValidationGasLimit
            treasury // treasury
        );

        if (preFundPresent > 0) {
            op.paymasterAndData = abi.encodePacked(op.paymasterAndData, preFundPresent);
        }

        if (constantFeePresent == 1) {
            op.paymasterAndData = abi.encodePacked(
                op.paymasterAndData,
                uint128(1) // constantFee
            );
        }

        if (recipientPresent == 1) {
            op.paymasterAndData = abi.encodePacked(
                op.paymasterAndData,
                address(0) // recipient is invalid and it should revert
            );
        }

        op.paymasterAndData = abi.encodePacked(op.paymasterAndData, "DummySignature");

        op.signature = signUserOp(op, userKey);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, uint256(0), "AA33 reverted (or OOG)"));
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

    function test_RevertWhen_RecipientTransferFailed() external {
        vm.assertEq(0, token.balanceOf(recipient));
        vm.assertEq(0, token.balanceOf(treasury));

        uint128 postOpGas = 50_000;
        uint256 userOperationGasUsed = 1_000_000;
        uint256 exchangeRate = 1e10;
        uint256 maxFeePerGas = 10 gwei;
        uint256 maxPriorityFeePerGas = 10 gwei;

        vm.assume(maxFeePerGas >= maxPriorityFeePerGas);

        uint256 actualUserOpFeePerGas;
        if (maxFeePerGas == maxPriorityFeePerGas) {
            // chains that only support legacy (pre EIP-1559 transactions)
            actualUserOpFeePerGas = maxFeePerGas;
        } else {
            actualUserOpFeePerGas = Math.min(maxFeePerGas, maxPriorityFeePerGas + block.basefee);
        }

        uint256 actualGasCost = userOperationGasUsed * actualUserOpFeePerGas;

        uint256 expectedCostInToken =
            paymaster.getCostInToken(actualGasCost, postOpGas, actualUserOpFeePerGas, exchangeRate);

        setupERC20Environment(expectedCostInToken);

        uint256 preFund = actualGasCost * 5;

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
                preFund: preFund,
                preFundCharged: uint256(0),
                executionGasLimit: uint256(0),
                preOpGasApproximation: uint256(0),
                constantFee: uint128(0),
                recipient: recipient
            })
        );

        vm.prank(address(entryPoint));
        vm.expectRevert(
            abi.encodeWithSelector(
                BaseSingletonPaymaster.PostOpTransferFromFailed.selector, "TRANSFER_TO_RECIPIENT_FAILED"
            )
        );
        paymaster.postOp(PostOpMode.opSucceeded, context, actualGasCost);
    }

    function test_RevertWhen_BundlerNotAllowed() external {
        setupERC20Environment(UINT256_MAX);

        // treasury should have no tokens
        assertEq(token.balanceOf(paymasterOwner), 0);

        UserOperation memory op = fillUserOp();
        op.paymasterAndData =
            getSignedPaymasterData(ERC20_MODE, ALLOW_WHITELISTED_BUNDLERS, op, uint8(0), uint8(0), uint8(0));
        op.signature = signUserOp(op, userKey);

        // check that UserOperationSponsored log is emitted.
        // event data check is skipped because we don't know how much will be spent.
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, uint256(0), "AA33 reverted (or OOG)"));

        submitUserOp(op);
    }

    function test_RevertWhen_OnlyBundlerAllowed() external {
        setupERC20Environment(UINT256_MAX);

        // treasury should have no tokens
        assertEq(token.balanceOf(treasury), 0);

        address[] memory bundlers = new address[](1);
        bundlers[0] = address(DEFAULT_SENDER);

        paymasterOwner = makeAddr("paymasterOwner");
        vm.prank(paymasterOwner);
        paymaster.updateBundlerAllowlist(bundlers, true);

        UserOperation memory op = fillUserOp();
        op.paymasterAndData =
            getSignedPaymasterData(ERC20_MODE, ALLOW_WHITELISTED_BUNDLERS, op, uint8(0), uint8(0), uint8(0));
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

    function test_RevertWhen_ERC20WithPreFundExceedsRequiredPreFund() external {
        setupERC20Environment(UINT256_MAX);

        // on chains that don't support EIP-1559, the UserOperation's maxFee & maxPriorityFee are equal.
        UserOperation memory op = fillUserOp();
        op.maxPriorityFeePerGas = 5;
        op.maxFeePerGas = 5;
        op.paymasterAndData =
            getSignedPaymasterData(ERC20_MODE, ALLOW_ALL_BUNDLERS, op, uint8(0), uint8(0), uint128(10_000_000_000));
        op.signature = signUserOp(op, userKey);

        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, uint256(0), "AA33 reverted (or OOG)"));
        submitUserOp(op);
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
        uint256 _exchangeRate,
        uint8 _constantFeePresent,
        uint8 _recipientPresent,
        uint128 _preFundPresent
    )
        external
    {
        uint8 constantFeePresent = uint8(bound(_constantFeePresent, 0, 1));
        uint8 recipientPresent = uint8(bound(_recipientPresent, 0, 1));
        uint128 preFundPresent = uint128(bound(_preFundPresent, 0, 1));
        vm.assume(_exchangeRate > 0);
        vm.assume(_exchangeRate < 1e24);
        vm.assume(_token != address(0));

        UserOperation memory op = fillUserOp();
        PaymasterData memory data = PaymasterData(address(paymaster), _validUntil, _validAfter, ALLOW_ALL_BUNDLERS);

        // Test with correct signature
        validateERC20PaymasterUserOp(
            op,
            data,
            _token,
            _postOpGas,
            _exchangeRate,
            0,
            paymasterSignerKey,
            constantFeePresent,
            recipientPresent,
            preFundPresent
        );

        // Test with incorrect signature
        validateERC20PaymasterUserOp(
            op,
            data,
            _token,
            _postOpGas,
            _exchangeRate,
            1,
            unauthorizedSignerKey,
            constantFeePresent,
            recipientPresent,
            preFundPresent
        );
    }

    function test_PostOpFirstTransferFromFailed() external {
        setupERC20Environment(UINT256_MAX);

        // treasury should have no tokens
        assertEq(token.balanceOf(treasury), 0);

        UserOperation memory op = fillUserOp();
        op.callData = abi.encodeWithSelector(
            SimpleAccount.execute.selector,
            address(token),
            0,
            // remove the approve during execution phase
            abi.encodeWithSelector(TestERC20.sudoApprove.selector, address(account), address(paymaster), 0)
        );
        op.paymasterAndData = getSignedPaymasterData(ERC20_MODE, ALLOW_ALL_BUNDLERS, op, uint8(0), uint8(0), uint8(0));
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

    // test that the treasury receives funds when postOp is called
    function test_postOpCalculation(
        uint256 _exchangeRate,
        uint128 _postOpGas,
        uint256 _userOperationGasUsed,
        uint256 _maxFeePerGas,
        uint256 _maxPriorityFeePerGas,
        uint256 _constantFee,
        uint8 _constantFeePresent,
        uint8 _recipientPresent,
        uint256 _preFund,
        uint256 _preFundCharged
    )
        external
    {
        token.sudoMint(address(account), 1e50);
        token.sudoApprove(address(account), address(paymaster), UINT256_MAX);
        token.sudoApprove(address(treasury), address(paymaster), UINT256_MAX);
        token.sudoMint(address(treasury), 1e50);
        vm.assertEq(0, token.balanceOf(recipient));

        uint128 postOpGas = uint128(bound(_postOpGas, 21_000, 250_000));
        uint256 userOperationGasUsed = bound(_userOperationGasUsed, 21_000, 30_000_000);
        uint256 exchangeRate = bound(_exchangeRate, 1e6, 1e20);
        uint256 maxFeePerGas = bound(_maxFeePerGas, 0.01 gwei, 5000 gwei);
        uint256 maxPriorityFeePerGas = bound(_maxPriorityFeePerGas, 0.01 gwei, 5000 gwei);
        uint128 constantFee = uint128(bound(_constantFee, 0, 1000));
        uint8 constantFeePresent = uint8(bound(_constantFeePresent, 0, 1));
        uint8 recipientPresent = uint8(bound(_recipientPresent, 0, 1));

        vm.assume(maxFeePerGas >= maxPriorityFeePerGas);

        uint256 actualUserOpFeePerGas;
        if (maxFeePerGas == maxPriorityFeePerGas) {
            // chains that only support legacy (pre EIP-1559 transactions)
            actualUserOpFeePerGas = maxFeePerGas;
        } else {
            actualUserOpFeePerGas = Math.min(maxFeePerGas, maxPriorityFeePerGas + block.basefee);
        }

        uint256 actualGasCost = userOperationGasUsed * actualUserOpFeePerGas;
        uint256 preFund = bound(_preFund, actualGasCost, actualGasCost * 2);
        uint256 preFundCharged = uint256(bound(_preFundCharged, 0 gwei, (preFund * exchangeRate) / 1e18));

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
                preFund: preFund,
                preFundCharged: preFundCharged,
                executionGasLimit: uint256(0),
                preOpGasApproximation: uint256(0),
                constantFee: constantFeePresent == 1 ? constantFee : uint128(0),
                recipient: recipientPresent == 1 ? recipient : address(0)
            })
        );

        validatePostOpCalculation(
            context,
            actualGasCost,
            postOpGas,
            actualUserOpFeePerGas,
            exchangeRate,
            constantFee,
            constantFeePresent,
            recipientPresent,
            preFund,
            preFundCharged
        );
    }

    function validatePostOpCalculation(
        bytes memory context,
        uint256 actualGasCost,
        uint128 postOpGas,
        uint256 actualUserOpFeePerGas,
        uint256 exchangeRate,
        uint128 constantFee,
        uint8 constantFeePresent,
        uint8 recipientPresent,
        uint256 preFund,
        uint256 preFundCharged
    )
        internal
    {
        uint256 balanceOfTreasury = token.balanceOf(treasury);
        vm.prank(address(entryPoint));
        paymaster.postOp(PostOpMode.opSucceeded, context, actualGasCost);
        uint256 expectedCostInTokenWithoutConstantFee =
            paymaster.getCostInToken(actualGasCost, postOpGas, actualUserOpFeePerGas, exchangeRate);

        uint256 expectedCostInToken = expectedCostInTokenWithoutConstantFee;

        if (constantFeePresent == 1) {
            expectedCostInToken = expectedCostInTokenWithoutConstantFee + constantFee;
        }

        if (preFundCharged <= expectedCostInToken) {
            vm.assertEq(expectedCostInToken - preFundCharged + balanceOfTreasury, token.balanceOf(treasury));
        }

        if (preFundCharged > expectedCostInToken) {
            vm.assertEq(balanceOfTreasury - (preFundCharged - expectedCostInToken), token.balanceOf(treasury));
        }

        uint256 preFundInToken = preFund * exchangeRate / 1e18;
        if (recipientPresent == 1 && preFundInToken > expectedCostInToken) {
            vm.assertEq(preFundInToken - expectedCostInToken, token.balanceOf(recipient));
        } else {
            vm.assertEq(0, token.balanceOf(recipient));
        }
    }

    function validateERC20PaymasterUserOp(
        UserOperation memory op,
        PaymasterData memory data,
        address tokenAddress,
        uint128 postOpGas,
        uint256 exchangeRate,
        uint160 expectedSignature,
        uint256 signerKey,
        uint8 constantFeePresent,
        uint8 recipientPresent,
        uint128 preFundPresent
    )
        internal
    {
        if (preFundPresent > 0) {
            tokenAddress = address(token);
            token.sudoMint(address(account), 1e18);
            token.sudoApprove(address(account), address(paymaster), UINT256_MAX);
        }

        op.paymasterAndData = getERC20ModeData(
            data,
            tokenAddress,
            postOpGas,
            exchangeRate,
            uint128(0),
            op,
            signerKey,
            constantFeePresent,
            recipientPresent,
            preFundPresent
        );
        op.signature = signUserOp(op, userKey);
        bytes32 opHash = getOpHash(op);

        uint256 requiredPreFund = 1 * 1e18;
        vm.prank(address(entryPoint));
        (bytes memory context, uint256 validationData) = paymaster.validatePaymasterUserOp(op, opHash, requiredPreFund);

        // Validation checks
        vm.assertEq(uint160(validationData), expectedSignature, "unexpected signature");
        vm.assertEq(uint48(validationData >> 160), data.validUntil);
        vm.assertEq(uint48(validationData >> (48 + 160)), data.validAfter);

        // Context checks
        validateContext(
            context,
            op,
            tokenAddress,
            exchangeRate,
            postOpGas,
            opHash,
            constantFeePresent,
            recipientPresent,
            preFundPresent
        );
    }

    function validateContext(
        bytes memory context,
        UserOperation memory op,
        address tokenAddress,
        uint256 exchangeRate,
        uint128 postOpGas,
        bytes32 opHash,
        uint8 constantFeePresent,
        uint8 recipientPresent,
        uint128 preFundPresent
    )
        internal
        view
    {
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
        vm.assertEq(
            ctx.constantFee,
            constantFeePresent == 1 ? uint256(1) : uint256(0),
            "encoded context constantFee should equal constantFee"
        );
        vm.assertEq(
            ctx.recipient,
            recipientPresent == 1 ? recipient : address(0),
            "encoded context recipient should equal recipient"
        );
        vm.assertEq(ctx.preFundCharged, preFundPresent, "encoded context preFund should equal preFundPresent");
    }

    function test_ValidateSignatureCorrectness() external {
        flipUserOperationBitsAndValidateSignature(ERC20_MODE, uint8(0), uint8(0), uint128(0));
        flipUserOperationBitsAndValidateSignature(VERIFYING_MODE, uint8(0), uint8(0), uint128(0));
    }

    function test_ValidateSignatureCorrectnessWithConstantFeeAndRecipient() external {
        flipUserOperationBitsAndValidateSignature(ERC20_MODE, uint8(0), uint8(1), uint128(0));
        flipUserOperationBitsAndValidateSignature(ERC20_MODE, uint8(1), uint8(0), uint128(0));
        flipUserOperationBitsAndValidateSignature(ERC20_MODE, uint8(1), uint8(1), uint128(0));
    }

    function testValidateSignatureCorrectnessWithPreFund() external {
        flipUserOperationBitsAndValidateSignature(ERC20_MODE, uint8(0), uint8(0), uint128(1));
    }

    function testValidateSignatureCorrectnessWithConstantFeeAndRecipientAndPreFund() external {
        flipUserOperationBitsAndValidateSignature(ERC20_MODE, uint8(0), uint8(1), uint128(1));
        flipUserOperationBitsAndValidateSignature(ERC20_MODE, uint8(1), uint8(0), uint128(1));
        flipUserOperationBitsAndValidateSignature(ERC20_MODE, uint8(1), uint8(1), uint128(1));
    }

    // HELPERS //

    function flipUserOperationBitsAndValidateSignature(
        uint8 _mode,
        uint8 _constantFeePresent,
        uint8 _recipientPresent,
        uint128 _preFundPresent
    )
        internal
    {
        UserOperation memory op = fillUserOp();
        op.paymasterAndData = getSignedPaymasterData(
            _mode, ALLOW_ALL_BUNDLERS, op, _constantFeePresent, _recipientPresent, _preFundPresent
        );
        op.signature = signUserOp(op, userKey);

        uint256 requiredPreFund = 0;

        if (_preFundPresent > 0) {
            token.sudoMint(address(account), 1000 * 1e18);
            token.sudoApprove(address(account), address(paymaster), UINT256_MAX);
            requiredPreFund = 1e18;
        }

        checkIsPaymasterSignatureValid(op, true, requiredPreFund);

        // flip each bit in userOperation and check that signature is invalid
        for (uint256 bitPosition = 0; bitPosition < 256; bitPosition++) {
            uint256 mask = 1 << bitPosition;

            if (bitPosition < 160) {
                op.sender = address(bytes20(op.sender) ^ bytes20(uint160(mask)));
                if (_preFundPresent > 0) {
                    token.sudoMint(address(op.sender), 3000 * 1e18);
                    token.sudoApprove(address(op.sender), address(paymaster), UINT256_MAX);
                    requiredPreFund = 1e18;
                }
                checkIsPaymasterSignatureValid(op, false, requiredPreFund);
                op.sender = address(bytes20(op.sender) ^ bytes20(uint160(mask)));
            }

            op.nonce = uint256(bytes32(op.nonce) ^ bytes32(mask));
            checkIsPaymasterSignatureValid(op, false, requiredPreFund);
            op.nonce = uint256(bytes32(op.nonce) ^ bytes32(mask));

            op.callGasLimit = uint256(bytes32(op.callGasLimit) ^ bytes32(mask));
            checkIsPaymasterSignatureValid(op, false, requiredPreFund);
            op.callGasLimit = uint256(bytes32(op.callGasLimit) ^ bytes32(mask));

            op.preVerificationGas = uint256(bytes32(op.preVerificationGas) ^ bytes32(mask));
            checkIsPaymasterSignatureValid(op, false, requiredPreFund);
            op.preVerificationGas = uint256(bytes32(op.preVerificationGas) ^ bytes32(mask));

            op.verificationGasLimit = uint256(bytes32(op.verificationGasLimit) ^ bytes32(mask));
            checkIsPaymasterSignatureValid(op, false, requiredPreFund);
            op.verificationGasLimit = uint256(bytes32(op.verificationGasLimit) ^ bytes32(mask));

            op.maxFeePerGas = uint256(bytes32(op.maxFeePerGas) ^ bytes32(mask));
            checkIsPaymasterSignatureValid(op, false, requiredPreFund);
            op.maxFeePerGas = uint256(bytes32(op.maxFeePerGas) ^ bytes32(mask));

            op.maxPriorityFeePerGas = uint256(bytes32(op.maxPriorityFeePerGas) ^ bytes32(mask));
            checkIsPaymasterSignatureValid(op, false, requiredPreFund);
            op.maxPriorityFeePerGas = uint256(bytes32(op.maxPriorityFeePerGas) ^ bytes32(mask));
        }

        // check initCode
        for (uint256 byteIndex = 0; byteIndex < op.initCode.length; byteIndex++) {
            for (uint8 bitPosition = 0; bitPosition < 8; bitPosition++) {
                uint256 mask = 1 << bitPosition;

                op.initCode[byteIndex] = bytes1(uint8(op.initCode[byteIndex]) ^ uint8(mask));
                checkIsPaymasterSignatureValid(op, false, requiredPreFund);
                op.initCode[byteIndex] = bytes1(uint8(op.initCode[byteIndex]) ^ uint8(mask));
            }
        }

        // check calldata
        for (uint256 byteIndex = 0; byteIndex < op.callData.length; byteIndex++) {
            for (uint8 bitPosition = 0; bitPosition < 8; bitPosition++) {
                uint256 mask = 1 << bitPosition;

                op.callData[byteIndex] = bytes1(uint8(op.callData[byteIndex]) ^ uint8(mask));
                checkIsPaymasterSignatureValid(op, false, requiredPreFund);
                op.callData[byteIndex] = bytes1(uint8(op.callData[byteIndex]) ^ uint8(mask));
            }
        }

        uint256 paymasterConfigLength = 20 + 1; // include mode and allowAllBundlers

        if (_mode == ERC20_MODE) {
            paymasterConfigLength += ERC20_PAYMASTER_DATA_LENGTH;

            if (_constantFeePresent == 1) {
                paymasterConfigLength += 16;
            }

            if (_recipientPresent == 1) {
                paymasterConfigLength += 20;
            }

            if (_preFundPresent == 1) {
                paymasterConfigLength += 16;
            }
        }

        if (_mode == VERIFYING_MODE) {
            paymasterConfigLength += VERIFYING_PAYMASTER_DATA_LENGTH;
        }

        // check paymasterAndData
        for (uint256 byteIndex = 0; byteIndex < paymasterConfigLength; byteIndex++) {
            // we don't want to flip the mode byte and allowAllBundlers byte
            if (byteIndex == 20) {
                continue;
            }

            // don't change constantFeePresent and recipientPresent
            if (_mode == ERC20_MODE && byteIndex == 21) {
                continue;
            }

            for (uint8 bitPosition = 0; bitPosition < 8; bitPosition++) {
                uint256 mask = 1 << bitPosition;

                op.paymasterAndData[byteIndex] = bytes1(uint8(op.paymasterAndData[byteIndex]) ^ uint8(mask));
                checkIsPaymasterSignatureValid(op, false, requiredPreFund);
                op.paymasterAndData[byteIndex] = bytes1(uint8(op.paymasterAndData[byteIndex]) ^ uint8(mask));
            }
        }
    }

    function checkIsPaymasterSignatureValid(
        UserOperation memory op,
        bool isSignatureValid,
        uint256 requiredPreFund
    )
        internal
    {
        bytes32 opHash = getOpHash(op);
        vm.prank(address(entryPoint));
        (, uint256 validationData) = paymaster.validatePaymasterUserOp(op, opHash, requiredPreFund);
        assertEq(uint160(validationData), isSignatureValid ? 0 : 1);
    }

    function getSignedPaymasterData(
        uint8 mode,
        uint8 allowAllBundlers,
        UserOperation memory userOp,
        uint8 constantFeePresent,
        uint8 recipientPresent,
        uint128 preFundPresent
    )
        private
        view
        returns (bytes memory)
    {
        PaymasterData memory data = PaymasterData({
            paymasterAddress: address(paymaster), validUntil: 0, validAfter: 0, allowAllBundlers: allowAllBundlers
        });

        if (mode == VERIFYING_MODE) {
            return getVerifyingModeData(data, userOp, paymasterSignerKey);
        } else if (mode == ERC20_MODE) {
            return getERC20ModeData(
                data,
                address(token),
                POSTOP_GAS,
                EXCHANGE_RATE,
                uint128(0),
                userOp,
                paymasterSignerKey,
                constantFeePresent,
                recipientPresent,
                preFundPresent
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
            address(paymaster),
            uint8((data.allowAllBundlers & 0x01) | (VERIFYING_MODE << 1)),
            data.validUntil,
            data.validAfter
        );
        bytes32 hash = paymaster.getHash(VERIFYING_MODE, userOp);
        bytes memory sig = getSignature(hash, signerKey);

        return abi.encodePacked(userOp.paymasterAndData, sig);
    }

    function getERC20ModeData(
        PaymasterData memory data,
        address erc20,
        uint128 postOpGas,
        uint256 exchangeRate,
        uint128 paymasterValidationGasLimit,
        UserOperation memory userOp,
        uint256 signerKey,
        uint8 constantFeePresent,
        uint8 recipientPresent,
        uint128 preFundPresent
    )
        private
        view
        returns (bytes memory)
    {
        userOp.paymasterAndData = abi.encodePacked(
            data.paymasterAddress,
            uint8((data.allowAllBundlers & 0x01) | (ERC20_MODE << 1)),
            uint8(
                (constantFeePresent == 1 ? 1 : 0) | (recipientPresent == 1 ? 1 << 1 : 0)
                    | (preFundPresent > 0 ? 1 << 2 : 0)
            ),
            data.validUntil,
            data.validAfter,
            erc20,
            postOpGas,
            exchangeRate,
            paymasterValidationGasLimit,
            treasury
        );

        if (preFundPresent != 0) {
            userOp.paymasterAndData = abi.encodePacked(userOp.paymasterAndData, preFundPresent);
        }

        if (constantFeePresent == 1) {
            uint128 constantFee = 1;
            userOp.paymasterAndData = abi.encodePacked(userOp.paymasterAndData, constantFee);
        }

        if (recipientPresent == 1) {
            userOp.paymasterAndData = abi.encodePacked(userOp.paymasterAndData, recipient);
        }

        bytes32 hash = paymaster.getHash(ERC20_MODE, userOp);
        bytes memory sig = getSignature(hash, signerKey);

        userOp.paymasterAndData = abi.encodePacked(userOp.paymasterAndData, sig);

        return userOp.paymasterAndData;
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

    function setupERC20Environment(uint256 approvalValue) private {
        token.sudoMint(address(account), 1000e18);
        token.sudoApprove(address(account), address(paymaster), approvalValue);
        token.sudoApprove(address(treasury), address(paymaster), UINT256_MAX);
    }
}
