// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { Test, console } from "forge-std/Test.sol";
import { MessageHashUtils } from "openzeppelin-contracts-v5.0.2/contracts/utils/cryptography/MessageHashUtils.sol";
import { IERC20 } from "openzeppelin-contracts-v5.0.2/contracts/token/ERC20/IERC20.sol";

import { IEntryPoint } from "@account-abstraction-v8/interfaces/IEntryPoint.sol";
import { PackedUserOperation } from "account-abstraction-v7/interfaces/PackedUserOperation.sol";
import {
    PackedUserOperation as PackedUserOperationV8
} from "account-abstraction-v8/interfaces/PackedUserOperation.sol";
import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";

import { ERC20PostOpContext, BaseSingletonPaymaster } from "../../src/base/BaseSingletonPaymaster.sol";
import { SingletonPaymasterV8 } from "../../src/SingletonPaymasterV8.sol";
import { PostOpMode } from "../../src/interfaces/PostOpMode.sol";

import {
    SimpleAccountFactory,
    SimpleAccount
} from "../utils/account-abstraction/v08/accounts/SimpleAccountFactory.sol";
import { EntryPoint } from "../utils/account-abstraction/v08/core/EntryPoint.sol";
import { BaseAccount } from "../utils/account-abstraction/v08/core/BaseAccount.sol";
import { TestERC20 } from "../utils/TestERC20.sol";
import { TestCounter } from "../utils/TestCounter.sol";

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

// The abstract base test contract for SingletonPaymasterV8
abstract contract BasePaymasterTestV8 is Test {
    // Common test constants
    uint8 immutable VERIFYING_MODE = 0;
    uint8 immutable ERC20_MODE = 1;
    uint8 immutable ALLOW_ALL_BUNDLERS = 1;
    uint8 immutable ALLOW_WHITELISTED_BUNDLERS = 0;
    uint256 immutable EXCHANGE_RATE = 3000 * 1e18;
    uint128 immutable POSTOP_GAS = 50_000;
    uint128 immutable PAYMASTER_VALIDATION_GAS_LIMIT = 30_000;

    // ECDSA signature constants
    uint8 immutable PAYMASTER_DATA_OFFSET = 52;
    uint8 immutable ERC20_PAYMASTER_DATA_LENGTH = 117;
    uint8 immutable MODE_AND_ALLOW_ALL_BUNDLERS_LENGTH = 1;
    uint8 immutable VERIFYING_PAYMASTER_DATA_LENGTH = 12;

    // Shared test variables
    address payable beneficiary;
    address paymasterOwner;
    address paymasterSigner;
    address treasury;
    address recipient;
    uint256 paymasterSignerKey;
    uint256 unauthorizedSignerKey;
    address user;
    uint256 userKey;
    address manager;
    SingletonPaymasterV8 paymaster;
    EntryPoint entryPoint;
    TestERC20 token;
    TestCounter counter;

    // Fixed address for the EntryPoint as expected by Simple7702Account
    address constant ENTRY_POINT_ADDRESS = 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108;

    // Abstract methods to be implemented by derived contracts
    function createAndFundAccount(address owner) internal virtual returns (address);

    function signUserOp(PackedUserOperation memory op, uint256 key) internal virtual returns (bytes memory);

    // Common setup
    function setUp() public virtual {
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

        // Create a temporary EntryPoint to get its code
        EntryPoint tempEntryPoint = new EntryPoint();

        // Get the runtime bytecode of the EntryPoint
        bytes memory entryPointCode = address(tempEntryPoint).code;

        // Set up the EntryPoint at the specific address
        vm.etch(ENTRY_POINT_ADDRESS, entryPointCode);

        // Now point to the EntryPoint at the specific address
        entryPoint = EntryPoint(payable(ENTRY_POINT_ADDRESS));

        // Account creation is done in child contracts

        paymaster = new SingletonPaymasterV8(ENTRY_POINT_ADDRESS, paymasterOwner, manager, new address[](0));
        paymaster.deposit{ value: 100e18 }();

        vm.prank(paymasterOwner);
        paymaster.addSigner(paymasterSigner);
    }

    // Shared test methods
    // Common helper and test declarations defined here for shared use

    function testDeployment() public virtual {
        SingletonPaymasterV8 subject =
            new SingletonPaymasterV8(address(entryPoint), paymasterOwner, manager, new address[](0));
        vm.prank(paymasterOwner);
        subject.addSigner(paymasterSigner);

        assertTrue(subject.hasRole(paymaster.DEFAULT_ADMIN_ROLE(), paymasterOwner));
        // assertEq(subject.treasury(), paymasterOwner);
        assertTrue(subject.signers(paymasterSigner));
    }

    function testERC20Success() public virtual {
        setupERC20Environment();

        // Get account from the child implementation
        address account = createAndFundAccount(user);

        // treasury should have no tokens
        assertEq(token.balanceOf(treasury), 0);

        PackedUserOperation memory op = fillUserOp(account);
        op.paymasterAndData = getSignedPaymasterData(ERC20_MODE, ALLOW_ALL_BUNDLERS, op, uint8(0), uint8(0), uint8(0));
        op.signature = signUserOp(op, userKey);

        // check that UserOperationSponsored log is emitted
        vm.expectEmit(true, true, true, false, address(paymaster));
        emit BaseSingletonPaymaster.UserOperationSponsored(
            getOpHash(op), op.sender, ERC20_MODE, address(token), 0, EXCHANGE_RATE
        );

        submitUserOp(op);

        // treasury should now have tokens
        assertGt(token.balanceOf(treasury), 0);
    }

    function testERC20WithConstantFeeSuccess() public virtual {
        setupERC20Environment();

        // Get account from the child implementation
        address account = createAndFundAccount(user);

        // treasury should have no tokens
        assertEq(token.balanceOf(treasury), 0);

        PackedUserOperation memory op = fillUserOp(account);
        op.paymasterAndData = getSignedPaymasterData(ERC20_MODE, ALLOW_ALL_BUNDLERS, op, uint8(1), uint8(0), uint8(0));
        op.signature = signUserOp(op, userKey);

        // check that UserOperationSponsored log is emitted.
        vm.expectEmit(true, true, true, false, address(paymaster));
        emit BaseSingletonPaymaster.UserOperationSponsored(
            getOpHash(op), op.sender, ERC20_MODE, address(token), 0, EXCHANGE_RATE
        );

        submitUserOp(op);

        // treasury should now have tokens
        assertGt(token.balanceOf(treasury), 0);
    }

    function testVerifyingSuccess() public virtual {
        // Get account from the child implementation
        address account = createAndFundAccount(user);

        PackedUserOperation memory op = fillUserOp(account);
        op.paymasterAndData =
            getSignedPaymasterData(VERIFYING_MODE, ALLOW_ALL_BUNDLERS, op, uint8(0), uint8(0), uint8(0));
        op.signature = signUserOp(op, userKey);

        // check that UserOperationSponsored log is emitted.
        vm.expectEmit(address(paymaster));
        emit BaseSingletonPaymaster.UserOperationSponsored(getOpHash(op), op.sender, VERIFYING_MODE, address(0), 0, 0);

        submitUserOp(op);
    }

    function test_ERC20WithPrefund() public virtual {
        setupERC20Environment();

        // Get account from the child implementation
        address account = createAndFundAccount(user);

        // treasury should have no tokens
        assertEq(token.balanceOf(treasury), 0);

        PackedUserOperation memory op = fillUserOp(account);
        op.paymasterAndData =
            getSignedPaymasterData(ERC20_MODE, ALLOW_ALL_BUNDLERS, op, uint8(0), uint8(0), uint128(1_000_000));
        op.signature = signUserOp(op, userKey);

        // check that UserOperationSponsored log is emitted.
        vm.expectEmit(true, true, true, false, address(paymaster));
        emit BaseSingletonPaymaster.UserOperationSponsored(
            getOpHash(op), op.sender, ERC20_MODE, address(token), 0, EXCHANGE_RATE
        );

        submitUserOp(op);

        // treasury should now have tokens
        assertGt(token.balanceOf(treasury), 0);
    }

    function test_RevertWhen_ERC20PaymasterSignatureInvalid() public virtual {
        // Get account from the child implementation
        address account = createAndFundAccount(user);

        PackedUserOperation memory op = fillUserOp(account);

        // sign with random private key to force false signature
        PaymasterData memory data = PaymasterData(address(paymaster), 50_000, 100_000, 0, 0, ALLOW_ALL_BUNDLERS);
        op.paymasterAndData = getERC20ModeData(
            data,
            address(token),
            POSTOP_GAS,
            EXCHANGE_RATE,
            PAYMASTER_VALIDATION_GAS_LIMIT,
            op,
            unauthorizedSignerKey,
            uint8(0),
            uint8(0),
            uint128(0)
        );
        op.signature = signUserOp(op, userKey);

        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, uint256(0), "AA34 signature error"));
        submitUserOp(op);
    }

    function test_RevertWhen_VerifyingPaymasterSignatureInvalid() public virtual {
        address account = createAndFundAccount(user);
        PackedUserOperation memory op = fillUserOp(account);

        PaymasterData memory data = PaymasterData(address(paymaster), 50_000, 100_000, 0, 0, ALLOW_ALL_BUNDLERS);
        op.paymasterAndData = getVerifyingModeData(data, op, unauthorizedSignerKey);
        op.signature = signUserOp(op, userKey);

        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, uint256(0), "AA34 signature error"));
        submitUserOp(op);
    }

    function test_RevertWhen_PaymasterModeInvalid(uint8 _invalidMode) public virtual {
        vm.assume(_invalidMode != ERC20_MODE && _invalidMode != VERIFYING_MODE);
        address account = createAndFundAccount(user);

        // When mode = 129 = '10000001'
        // 1  & 0x01 | mode << 1 = 259 = '100000011'
        // but since we have only 8 bits,
        // '100000011' becomes '00000011'
        // and
        // '00000011' becomes 3 which is valid mode
        // so we need to make sure that _invalidMode is less than 127 = '1111111'
        vm.assume(_invalidMode < 127);

        PackedUserOperation memory op = fillUserOp(account);

        op.paymasterAndData = abi.encodePacked(
            address(paymaster),
            uint128(100_000),
            uint128(50_000),
            uint8((ALLOW_ALL_BUNDLERS & 0x01) | (_invalidMode << 1))
        );
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

    function test_RevertWhen_PaymasterConfigLengthInvalid(uint8 _mode, bytes calldata _randomBytes) public virtual {
        uint8 mode = uint8(bound(_mode, 0, 1));
        address account = createAndFundAccount(user);
        setupERC20Environment();

        if (mode == VERIFYING_MODE) {
            vm.assume(_randomBytes.length < 12);
        }

        if (mode == ERC20_MODE) {
            vm.assume(_randomBytes.length < ERC20_PAYMASTER_DATA_LENGTH);
        }

        PackedUserOperation memory op = fillUserOp(account);

        op.paymasterAndData = abi.encodePacked(
            address(paymaster),
            uint128(100_000),
            uint128(50_000),
            uint8((ALLOW_ALL_BUNDLERS & 0x01) | (mode << 1)),
            _randomBytes
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

    function test_RevertWhen_PaymasterSignatureLengthInvalid(uint8 _mode) public virtual {
        uint8 mode = uint8(bound(_mode, 0, 1));
        address account = createAndFundAccount(user);
        setupERC20Environment();

        PackedUserOperation memory op = fillUserOp(account);

        if (mode == VERIFYING_MODE) {
            op.paymasterAndData = abi.encodePacked(
                address(paymaster), // paymaster
                uint128(100_000), // paymaster verification gas
                uint128(50_000), // paymaster postop gas
                uint8((ALLOW_ALL_BUNDLERS & 0x01) | (mode << 1)),
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
                uint8((ALLOW_ALL_BUNDLERS & 0x01) | (mode << 1)), // mode & allowAllBundlers
                uint8((uint8(0) & 0x01) | (uint8(0) << 1)), // constantFeePresent & recipientPresent
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
                treasury, // treasury
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

    function test_RevertWhen_TokenAddressInvalid(
        uint8 _constantFeePresent,
        uint8 _recipientPresent,
        uint8 _preFundPresent
    )
        public
        virtual
    {
        uint8 constantFeePresent = uint8(bound(_constantFeePresent, 0, 1));
        uint8 recipientPresent = uint8(bound(_recipientPresent, 0, 1));
        uint128 preFundPresent = uint128(bound(_preFundPresent, 0, 1));
        address account = createAndFundAccount(user);
        setupERC20Environment();

        PackedUserOperation memory op = fillUserOp(account);

        op.paymasterAndData = abi.encodePacked(
            address(paymaster), // paymaster
            uint128(100_000), // paymaster verification gas
            uint128(50_000), // paymaster postop gas
            uint8((ALLOW_ALL_BUNDLERS & 0x01) | (ERC20_MODE << 1)),
            uint8(
                (constantFeePresent == 1 ? 1 : 0) | (recipientPresent == 1 ? 1 << 1 : 0)
                    | (preFundPresent > 0 ? 1 << 2 : 0)
            ),
            uint48(0), // validUntil
            int48(0), // validAfter
            address(0), // token will throw here, token address cannot be zero
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
            op.paymasterAndData = abi.encodePacked(
                op.paymasterAndData,
                preFundPresent // preFund
            );
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
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                uint256(0),
                string("AA33 reverted"),
                abi.encodeWithSelector(BaseSingletonPaymaster.TokenAddressInvalid.selector)
            )
        );
        submitUserOp(op);
    }

    function test_RevertWhen_ExchangeRateInvalid(
        uint8 _constantFeePresent,
        uint8 _recipientPresent,
        uint8 _preFundPresent
    )
        public
        virtual
    {
        uint8 constantFeePresent = uint8(bound(_constantFeePresent, 0, 1));
        uint8 recipientPresent = uint8(bound(_recipientPresent, 0, 1));
        uint128 preFundPresent = uint128(bound(_preFundPresent, 0, 1));
        address account = createAndFundAccount(user);
        setupERC20Environment();

        PackedUserOperation memory op = fillUserOp(account);

        op.paymasterAndData = abi.encodePacked(
            address(paymaster), // paymaster
            uint128(100_000), // paymaster verification gas
            uint128(50_000), // paymaster postop gas
            uint8((ALLOW_ALL_BUNDLERS & 0x01) | (ERC20_MODE << 1)),
            uint8(
                (constantFeePresent == 1 ? 1 : 0) | (recipientPresent == 1 ? 1 << 1 : 0)
                    | (preFundPresent > 0 ? 1 << 2 : 0)
            ),
            uint48(0), // validUntil
            int48(0), // validAfter
            address(token), // token
            uint128(1), // postOpGas
            uint256(0) // exchangeRate will throw here, price cannot be zero
        );

        // split into 2 parts to avoid stack too deep
        op.paymasterAndData = abi.encodePacked(
            op.paymasterAndData,
            uint128(0), // paymasterValidationGasLimit
            treasury // treasury
        );

        if (preFundPresent > 0) {
            op.paymasterAndData = abi.encodePacked(
                op.paymasterAndData,
                preFundPresent // preFund
            );
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
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                uint256(0),
                "AA33 reverted",
                abi.encodeWithSelector(BaseSingletonPaymaster.ExchangeRateInvalid.selector)
            )
        );
        submitUserOp(op);
    }

    function test_RevertWhen_PaymasterAndDataLengthInvalid() public virtual {
        address account = createAndFundAccount(user);
        setupERC20Environment();

        PackedUserOperation memory op = fillUserOp(account);

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

        test_RevertWhen_PaymasterAndDataLengthInvalid_helper(uint8(0), uint8(1), uint128(0), account);
        test_RevertWhen_PaymasterAndDataLengthInvalid_helper(uint8(1), uint8(0), uint128(0), account);
        test_RevertWhen_PaymasterAndDataLengthInvalid_helper(uint8(1), uint8(1), uint128(0), account);

        test_RevertWhen_PaymasterAndDataLengthInvalid_helper(uint8(0), uint8(1), uint128(1_000_000), account);
        test_RevertWhen_PaymasterAndDataLengthInvalid_helper(uint8(1), uint8(0), uint128(1_000_000), account);
        test_RevertWhen_PaymasterAndDataLengthInvalid_helper(uint8(1), uint8(1), uint128(1_000_000), account);
    }

    function test_RevertWhen_PaymasterAndDataLengthInvalid_helper(
        uint8 constantFeePresent,
        uint8 recipientPresent,
        uint128 preFundPresent,
        address account
    )
        internal
    {
        PackedUserOperation memory op = fillUserOp(account);

        op.paymasterAndData = abi.encodePacked(
            address(paymaster), // paymaster
            uint128(100_000), // paymaster verification gas
            uint128(50_000), // paymaster postop gas
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
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                uint256(0),
                "AA33 reverted",
                abi.encodeWithSelector(BaseSingletonPaymaster.PaymasterConfigLengthInvalid.selector)
            )
        );
        submitUserOp(op);
    }

    function test_RevertWhen_InvalidRecipient(uint8 _constantFeePresent, uint8 _preFundPresent) public virtual {
        uint8 constantFeePresent = uint8(bound(_constantFeePresent, 0, 1));
        uint128 preFundPresent = uint128(bound(_preFundPresent, 0, 1));
        address account = createAndFundAccount(user);

        uint8 recipientPresent = uint8(1);

        PackedUserOperation memory op = fillUserOp(account);

        op.paymasterAndData = abi.encodePacked(
            address(paymaster), // paymaster
            uint128(100_000), // paymaster verification gas
            uint128(50_000), // paymaster postop gas
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
            op.paymasterAndData = abi.encodePacked(
                op.paymasterAndData,
                preFundPresent // preFund
            );
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
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                uint256(0),
                "AA33 reverted",
                abi.encodeWithSelector(BaseSingletonPaymaster.RecipientInvalid.selector)
            )
        );
        submitUserOp(op);
    }

    function test_RevertWhen_PostOpTransferFromFailed(
        uint8 _constantFeePresent,
        uint8 _recipientPresent
    )
        public
        virtual
    {
        uint8 constantFeePresent = uint8(bound(_constantFeePresent, 0, 1));
        uint8 recipientPresent = uint8(bound(_recipientPresent, 0, 1));
        address account = createAndFundAccount(user);

        PackedUserOperation memory op = fillUserOp(account);

        op.paymasterAndData = getSignedPaymasterData(
            ERC20_MODE, ALLOW_ALL_BUNDLERS, op, constantFeePresent, recipientPresent, uint128(0)
        );
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

    function test_PostOpFirstTransferFromFailed() public virtual {
        address account = createAndFundAccount(user);
        setupERC20Environment();

        // treasury should have no tokens
        assertEq(token.balanceOf(treasury), 0);

        PackedUserOperation memory op = fillUserOp(account);
        op.callData = abi.encodeWithSelector(
            BaseAccount.execute.selector,
            address(token),
            0,
            // remove the approve during execution phase
            abi.encodeWithSelector(TestERC20.sudoApprove.selector, address(account), address(paymaster), 0)
        );
        op.paymasterAndData = getSignedPaymasterData(ERC20_MODE, ALLOW_ALL_BUNDLERS, op, uint8(0), uint8(0), uint8(0));
        op.signature = signUserOp(op, userKey);

        // check that UserOperationSponsored log is emitted.
        vm.expectEmit(true, true, true, false, address(entryPoint));
        emit IEntryPoint.UserOperationEvent(getOpHash(op), op.sender, address(paymaster), op.nonce, true, 0, 0);

        submitUserOp(op);

        assertEq(token.balanceOf(treasury), 0);
    }

    function test_postOpCalculation(
        uint256 _exchangeRate,
        uint128 _postOpGas,
        uint256 _userOperationGasUsed,
        uint256 _actualUserOpFeePerGas,
        uint256 _constantFee,
        uint8 _constantFeePresent,
        uint8 _recipientPresent,
        uint256 _preFund
    )
        public
        virtual
    {
        address account = createAndFundAccount(user);
        token.sudoMint(account, 1e50);
        token.sudoApprove(account, address(paymaster), type(uint256).max);

        vm.assertEq(0, token.balanceOf(recipient));
        vm.assertEq(0, token.balanceOf(treasury));

        uint128 postOpGas = uint128(bound(_postOpGas, 21_000, 250_000));
        uint256 actualUserOpFeePerGas = bound(_actualUserOpFeePerGas, 0.01 gwei, 5000 gwei);
        uint256 userOperationGasUsed = bound(_userOperationGasUsed, 21_000, 30_000_000);
        uint256 exchangeRate = bound(_exchangeRate, 1e6, 1e24);
        uint128 constantFee = uint128(bound(_constantFee, 1e6, 1e20));
        uint8 constantFeePresent = uint8(bound(_constantFeePresent, 0, 1));
        uint8 recipientPresent = uint8(bound(_recipientPresent, 0, 1));

        uint256 actualGasCost = userOperationGasUsed * actualUserOpFeePerGas;

        uint256 preFund = bound(_preFund, actualGasCost, actualGasCost * 2);

        bytes memory context = abi.encode(
            ERC20PostOpContext({
                sender: account,
                token: address(token),
                treasury: address(treasury),
                exchangeRate: exchangeRate,
                postOpGas: postOpGas,
                userOpHash: 0x0000000000000000000000000000000000000000000000000000000000000000,
                maxFeePerGas: 0,
                maxPriorityFeePerGas: 0,
                preFund: preFund,
                preFundCharged: uint256(0),
                executionGasLimit: uint256(0),
                preOpGasApproximation: uint256(0),
                constantFee: constantFeePresent == 1 ? constantFee : uint128(0),
                recipient: recipientPresent == 1 ? recipient : address(0)
            })
        );

        uint256 expectedCostInTokenWithoutConstantFee =
            paymaster.getCostInToken(actualGasCost, postOpGas, actualUserOpFeePerGas, exchangeRate);

        uint256 expectedCostInToken = constantFeePresent == 1
            ? expectedCostInTokenWithoutConstantFee + constantFee
            : expectedCostInTokenWithoutConstantFee;

        vm.prank(address(entryPoint));
        paymaster.postOp(PostOpMode.opSucceeded, context, actualGasCost, actualUserOpFeePerGas);

        // TODO: Check when preOpGasApproximation is not 0
        vm.assertEq(expectedCostInToken, token.balanceOf(treasury));

        uint256 preFundInToken = (preFund * exchangeRate) / 1e18;
        if (recipientPresent == 1 && preFundInToken > expectedCostInToken) {
            vm.assertEq(preFundInToken - expectedCostInToken, token.balanceOf(recipient));
        } else {
            vm.assertEq(0, token.balanceOf(recipient));
        }
    }

    function test_postOpCalculation_withPenalty(
        uint256 _exchangeRate,
        uint128 _postOpGas,
        uint256 _userOperationGasUsed,
        uint256 _actualUserOpFeePerGas,
        uint256 _constantFee,
        uint8 _constantFeePresent,
        uint8 _recipientPresent,
        uint256 _preFund
    )
        public
        virtual
    {
        address account = createAndFundAccount(user);
        token.sudoMint(account, 1e50);
        token.sudoApprove(account, address(paymaster), type(uint256).max);

        vm.assertEq(0, token.balanceOf(recipient));
        vm.assertEq(0, token.balanceOf(treasury));

        uint128 postOpGas = uint128(bound(_postOpGas, 21_000, 250_000));
        uint256 actualUserOpFeePerGas = bound(_actualUserOpFeePerGas, 0.01 gwei, 5000 gwei);
        uint256 userOperationGasUsed = bound(_userOperationGasUsed, 21_000, 30_000_000);
        uint256 exchangeRate = bound(_exchangeRate, 1e6, 1e24);
        uint128 constantFee = uint128(bound(_constantFee, 0, 1000));
        uint8 constantFeePresent = uint8(bound(_constantFeePresent, 0, 1));
        uint8 recipientPresent = uint8(bound(_recipientPresent, 0, 1));

        uint256 actualGasCost = userOperationGasUsed * actualUserOpFeePerGas;

        uint256 preFund = bound(_preFund, actualGasCost, actualGasCost * 2);

        // uint256 preOpGasApproximation = uint256(0);
        // uint256 executionGasLimit = uint256(userOperationGasUsed * 2);

        bytes memory context = abi.encode(
            ERC20PostOpContext({
                sender: account,
                token: address(token),
                treasury: address(treasury),
                exchangeRate: exchangeRate,
                postOpGas: postOpGas,
                userOpHash: 0x0000000000000000000000000000000000000000000000000000000000000000,
                maxFeePerGas: 0,
                maxPriorityFeePerGas: 0,
                preOpGasApproximation: uint256(0),
                executionGasLimit: uint256(userOperationGasUsed * 2),
                preFund: preFund,
                preFundCharged: uint256(0),
                constantFee: constantFeePresent == 1 ? constantFee : uint128(0),
                recipient: recipientPresent == 1 ? recipient : address(0)
            })
        );

        vm.prank(address(entryPoint));
        paymaster.postOp(PostOpMode.opSucceeded, context, actualGasCost, actualUserOpFeePerGas);

        uint256 expectedPenaltyGasCost = paymaster._expectedPenaltyGasCost(
            actualGasCost, actualUserOpFeePerGas, postOpGas, uint256(0), uint256(userOperationGasUsed * 2)
        );

        uint256 expectedCostInTokenWithoutConstantFee = paymaster.getCostInToken(
            actualGasCost + expectedPenaltyGasCost, postOpGas, actualUserOpFeePerGas, exchangeRate
        );

        uint256 expectedCostInToken = constantFeePresent == 1
            ? expectedCostInTokenWithoutConstantFee + constantFee
            : expectedCostInTokenWithoutConstantFee;

        vm.assertEq(expectedCostInToken, token.balanceOf(treasury));

        uint256 preFundInToken = (preFund * exchangeRate) / 1e18;
        if (recipientPresent == 1 && preFundInToken > expectedCostInToken) {
            vm.assertEq(preFundInToken - expectedCostInToken, token.balanceOf(recipient));
        } else {
            vm.assertEq(0, token.balanceOf(recipient));
        }
    }

    function test_RevertWhen_BundlerNotAllowed() public virtual {
        address account = createAndFundAccount(user);
        setupERC20Environment();

        // treasury should have no tokens
        assertEq(token.balanceOf(treasury), 0);

        PackedUserOperation memory op = fillUserOp(account);
        op.paymasterAndData =
            getSignedPaymasterData(ERC20_MODE, ALLOW_WHITELISTED_BUNDLERS, op, uint8(0), uint8(0), uint8(0));
        op.signature = signUserOp(op, userKey);

        // check that UserOperationSponsored log is emitted.
        // Get the tx.origin that will be used in the test environment
        address testEnvironmentTxOrigin = DEFAULT_SENDER;

        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                uint256(0),
                "AA33 reverted",
                abi.encodeWithSelector(BaseSingletonPaymaster.BundlerNotAllowed.selector, testEnvironmentTxOrigin)
            )
        );

        submitUserOp(op);
    }

    function test_RevertWhen_OnlyBundlerAllowed() public virtual {
        address account = createAndFundAccount(user);
        setupERC20Environment();

        // treasury should have no tokens
        assertEq(token.balanceOf(treasury), 0);

        address[] memory bundlers = new address[](1);
        bundlers[0] = DEFAULT_SENDER;

        vm.prank(paymasterOwner);
        paymaster.updateBundlerAllowlist(bundlers, true);

        PackedUserOperation memory op = fillUserOp(account);
        op.paymasterAndData =
            getSignedPaymasterData(ERC20_MODE, ALLOW_WHITELISTED_BUNDLERS, op, uint8(0), uint8(0), uint8(0));
        op.signature = signUserOp(op, userKey);

        // check that UserOperationSponsored log is emitted.
        vm.expectEmit(true, true, true, false, address(paymaster));
        emit BaseSingletonPaymaster.UserOperationSponsored(
            getOpHash(op), op.sender, ERC20_MODE, address(token), 0, EXCHANGE_RATE
        );

        submitUserOp(op);

        // treasury should now have tokens
        assertGt(token.balanceOf(treasury), 0);
    }

    function test_RevertWhen_NonEntryPointCaller() public virtual {
        vm.expectRevert("Sender not EntryPoint");
        paymaster.postOp(
            PostOpMode.opSucceeded,
            abi.encodePacked(address(0), address(token), uint256(5), bytes32(0), uint256(0), uint256(0)),
            0,
            0
        );

        PackedUserOperation memory op = fillUserOp(createAndFundAccount(user));
        bytes32 opHash = getOpHash(op);
        vm.expectRevert("Sender not EntryPoint");
        paymaster.validatePaymasterUserOp(op, opHash, 0);
    }

    function test_RevertWhen_ERC20WithPreFundExceedsRequiredPreFund() public virtual {
        address account = createAndFundAccount(user);
        setupERC20Environment();

        // treasury should have no tokens
        assertEq(token.balanceOf(treasury), 0);

        PackedUserOperation memory op = fillUserOp(account);
        op.paymasterAndData = getSignedPaymasterData(
            ERC20_MODE,
            ALLOW_ALL_BUNDLERS,
            op,
            uint8(0),
            uint8(0),
            uint128(1_000_000_000_000_000_000_000_000_000_000_000)
        );
        op.signature = signUserOp(op, userKey);

        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                uint256(0),
                string("AA33 reverted"),
                abi.encodeWithSelector(BaseSingletonPaymaster.PreFundTooHigh.selector)
            )
        );
        submitUserOp(op);
    }

    function test_veryfingValidatePaymasterUserOp(
        uint48 _validUntil,
        uint48 _validAfter,
        uint128 _paymasterPostOpGas,
        uint128 _paymasterVerificationGas
    )
        public
        virtual
    {
        address account = createAndFundAccount(user);
        PackedUserOperation memory op = fillUserOp(account);
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

    function test_verifyingValidatePaymasterUserOp(uint48 _validUntil, uint48 _validAfter) public virtual {
        address account = createAndFundAccount(user);
        PackedUserOperation memory op = fillUserOp(account);
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

    function test_ERC20ValidatePaymasterUserOp(
        uint48 _validUntil,
        uint48 _validAfter,
        address _token,
        uint128 _postOpGas,
        uint256 _exchangeRate,
        uint8 _constantFeePresent,
        uint8 _recipientPresent,
        uint8 _preFundPresent
    )
        public
        virtual
    {
        uint8 constantFeePresent = uint8(bound(_constantFeePresent, 0, 1));
        uint8 recipientPresent = uint8(bound(_recipientPresent, 0, 1));
        uint8 preFundPresent = uint8(bound(_preFundPresent, 0, 1));
        vm.assume(_exchangeRate > 0);
        vm.assume(_exchangeRate < 1e24);
        vm.assume(_token != address(0));
        address account = createAndFundAccount(user);

        PackedUserOperation memory op = fillUserOp(account);
        PaymasterData memory data =
            PaymasterData(address(paymaster), 50_000, 100_000, _validUntil, _validAfter, ALLOW_ALL_BUNDLERS);

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

    function validateERC20PaymasterUserOp(
        PackedUserOperation memory op,
        PaymasterData memory data,
        address tokenAddress,
        uint128 postOpGas,
        uint256 exchangeRate,
        uint160 expectedSignature,
        uint256 signerKey,
        uint8 constantFeePresent,
        uint8 recipientPresent,
        uint8 preFundPresent
    )
        internal
    {
        if (preFundPresent > 0) {
            tokenAddress = address(token);
            token.sudoMint(op.sender, 1e18);
            token.sudoApprove(op.sender, address(paymaster), type(uint256).max);
        }
        op.paymasterAndData = getERC20ModeData(
            data,
            tokenAddress,
            postOpGas,
            exchangeRate,
            PAYMASTER_VALIDATION_GAS_LIMIT,
            op,
            signerKey,
            constantFeePresent,
            recipientPresent,
            preFundPresent
        );
        op.signature = signUserOp(op, userKey);
        bytes32 opHash = getOpHash(op);

        vm.prank(address(entryPoint));
        uint256 requiredPreFund = 1 * 1e18;
        (bytes memory context, uint256 validationData) = paymaster.validatePaymasterUserOp(op, opHash, requiredPreFund);

        // Validation checks
        vm.assertEq(uint160(validationData), expectedSignature, "unexpected signature");
        vm.assertEq(uint48(validationData >> 160), data.validUntil);
        vm.assertEq(uint48(validationData >> (48 + 160)), data.validAfter);

        validateContext(
            context,
            op,
            tokenAddress,
            postOpGas,
            exchangeRate,
            opHash,
            constantFeePresent,
            recipientPresent,
            preFundPresent
        );
    }

    function validateContext(
        bytes memory context,
        PackedUserOperation memory op,
        address tokenAddress,
        uint128 postOpGas,
        uint256 exchangeRate,
        bytes32 opHash,
        uint8 constantFeePresent,
        uint8 recipientPresent,
        uint8 preFundPresent
    )
        internal
        view
    {
        // Context checks
        ERC20PostOpContext memory ctx = abi.decode(context, (ERC20PostOpContext));
        vm.assertEq(ctx.sender, op.sender, "encoded context sender should equal userOperation.sender");
        vm.assertEq(ctx.token, tokenAddress, "encoded context token should equal token");
        vm.assertEq(ctx.exchangeRate, exchangeRate, "encoded context exchangeRate should equal exchangeRate");
        vm.assertEq(ctx.postOpGas, postOpGas, "encoded context postOpGas should equal postOpGas");
        vm.assertEq(ctx.userOpHash, opHash, "encoded context opHash should equal opHash");
        vm.assertEq(ctx.maxFeePerGas, 0, "encoded context maxFeePerGas should equal to 0");
        vm.assertEq(ctx.maxPriorityFeePerGas, 0, "encoded context maxPriorityFeePerGas should equal to 0");
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

    function testValidateSignatureCorrectness() public virtual {
        address account = createAndFundAccount(user);
        flipUserOperationBitsAndValidateSignature(ERC20_MODE, uint8(0), uint8(0), uint128(0), account);
        flipUserOperationBitsAndValidateSignature(VERIFYING_MODE, uint8(0), uint8(0), uint128(0), account);
    }

    function testValidateSignatureCorrectnessWithConstantFeeAndRecipient() public virtual {
        address account = createAndFundAccount(user);
        flipUserOperationBitsAndValidateSignature(ERC20_MODE, uint8(0), uint8(1), uint128(0), account);
        flipUserOperationBitsAndValidateSignature(ERC20_MODE, uint8(1), uint8(0), uint128(0), account);
        flipUserOperationBitsAndValidateSignature(ERC20_MODE, uint8(1), uint8(1), uint128(0), account);
    }

    function testValidateSignatureCorrectnessWithPreFund() public virtual {
        address account = createAndFundAccount(user);
        flipUserOperationBitsAndValidateSignature(ERC20_MODE, uint8(0), uint8(0), uint128(1), account);
    }

    function testValidateSignatureCorrectnessWithConstantFeeAndRecipientAndPreFund() public virtual {
        address account = createAndFundAccount(user);
        flipUserOperationBitsAndValidateSignature(ERC20_MODE, uint8(0), uint8(1), uint128(1), account);
        flipUserOperationBitsAndValidateSignature(ERC20_MODE, uint8(1), uint8(0), uint128(1), account);
        flipUserOperationBitsAndValidateSignature(ERC20_MODE, uint8(1), uint8(1), uint128(1), account);
    }

    function flipUserOperationBitsAndValidateSignature(
        uint8 _mode,
        uint8 _constantFeePresent,
        uint8 _recipientPresent,
        uint128 _preFundPresent,
        address account
    )
        internal
    {
        PackedUserOperation memory op = fillUserOp(account);
        op.paymasterAndData = getSignedPaymasterData(
            _mode, ALLOW_ALL_BUNDLERS, op, _constantFeePresent, _recipientPresent, _preFundPresent
        );
        op.signature = signUserOp(op, userKey);

        uint256 requiredPreFund = 0;

        if (_preFundPresent > 0) {
            token.sudoMint(account, 1000 * 1e18);
            token.sudoApprove(account, address(paymaster), type(uint256).max);
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
                    token.sudoApprove(address(op.sender), address(paymaster), type(uint256).max);
                    requiredPreFund = 1e18;
                }
                checkIsPaymasterSignatureValid(op, false, requiredPreFund);
                op.sender = address(bytes20(op.sender) ^ bytes20(uint160(mask)));
            }

            op.nonce = uint256(bytes32(op.nonce) ^ bytes32(mask));
            checkIsPaymasterSignatureValid(op, false, requiredPreFund);
            op.nonce = uint256(bytes32(op.nonce) ^ bytes32(mask));

            op.accountGasLimits = bytes32(op.accountGasLimits) ^ bytes32(mask);
            checkIsPaymasterSignatureValid(op, false, requiredPreFund);
            op.accountGasLimits = bytes32(op.accountGasLimits) ^ bytes32(mask);

            op.preVerificationGas = uint256(bytes32(op.preVerificationGas) ^ bytes32(mask));
            checkIsPaymasterSignatureValid(op, false, requiredPreFund);
            op.preVerificationGas = uint256(bytes32(op.preVerificationGas) ^ bytes32(mask));

            op.gasFees = bytes32(op.gasFees) ^ bytes32(mask);
            checkIsPaymasterSignatureValid(op, false, requiredPreFund);
            op.gasFees = bytes32(op.gasFees) ^ bytes32(mask);
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

        // check initCode
        for (uint256 byteIndex = 0; byteIndex < op.initCode.length; byteIndex++) {
            for (uint8 bitPosition = 0; bitPosition < 8; bitPosition++) {
                uint256 mask = 1 << bitPosition;

                op.initCode[byteIndex] = bytes1(uint8(op.initCode[byteIndex]) ^ uint8(mask));
                checkIsPaymasterSignatureValid(op, false, requiredPreFund);
                op.initCode[byteIndex] = bytes1(uint8(op.initCode[byteIndex]) ^ uint8(mask));
            }
        }

        uint256 paymasterConfigLength = PAYMASTER_DATA_OFFSET + MODE_AND_ALLOW_ALL_BUNDLERS_LENGTH; // include mode and
        // allowAllBundlers

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
            if (byteIndex == 52) {
                continue;
            }

            // don't change constantFeePresent, recipientPresent, preFundPresent
            if (_mode == ERC20_MODE && byteIndex == 53) {
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
        PackedUserOperation memory op,
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

    // Helper methods
    function fillUserOp(address accountAddress) internal view returns (PackedUserOperation memory op) {
        op.sender = accountAddress;
        op.nonce = entryPoint.getNonce(accountAddress, 0);
        op.callData = abi.encodeWithSelector(
            BaseAccount.execute.selector, address(counter), 0, abi.encodeWithSelector(TestCounter.count.selector)
        );
        op.accountGasLimits = bytes32(abi.encodePacked(bytes16(uint128(80_000)), bytes16(uint128(50_000))));
        op.preVerificationGas = 50_000;
        op.gasFees = bytes32(abi.encodePacked(bytes16(uint128(100)), bytes16(uint128(1_000_000_000))));
        return op;
    }

    function getOpHash(PackedUserOperation memory op) internal view returns (bytes32) {
        PackedUserOperationV8 memory opV8 = convertToPackedUserOperationV8(op);
        return entryPoint.getUserOpHash(opV8);
    }

    function convertToPackedUserOperationV8(PackedUserOperation memory op)
        internal
        pure
        returns (PackedUserOperationV8 memory)
    {
        return PackedUserOperationV8({
            sender: op.sender,
            nonce: op.nonce,
            initCode: op.initCode,
            callData: op.callData,
            accountGasLimits: op.accountGasLimits,
            preVerificationGas: op.preVerificationGas,
            gasFees: op.gasFees,
            paymasterAndData: op.paymasterAndData,
            signature: op.signature
        });
    }

    function submitUserOp(PackedUserOperation memory op) public {
        PackedUserOperationV8[] memory opsV8 = new PackedUserOperationV8[](1);
        opsV8[0] = convertToPackedUserOperationV8(op);
        entryPoint.handleOps(opsV8, beneficiary);
    }

    function setupERC20Environment() internal {
        // Get account address from child implementation
        address account = createAndFundAccount(user);

        token.sudoMint(account, 1000e18);
        token.sudoMint(address(paymaster), 1);
        token.sudoApprove(account, address(paymaster), type(uint256).max);
        token.sudoApprove(address(treasury), address(paymaster), type(uint256).max);
    }

    function getSignedPaymasterData(
        uint8 mode,
        uint8 allowAllBundlers,
        PackedUserOperation memory userOp,
        uint8 constantFeePresent,
        uint8 recipientPresent,
        uint128 preFundPresent
    )
        internal
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
        } else if (mode == ERC20_MODE) {
            return getERC20ModeData(
                data,
                address(token),
                POSTOP_GAS,
                EXCHANGE_RATE,
                PAYMASTER_VALIDATION_GAS_LIMIT,
                userOp,
                paymasterSignerKey,
                constantFeePresent,
                recipientPresent,
                preFundPresent
            );
        }

        revert("unexpected mode");
    }

    function getVerifyingModeData(
        PaymasterData memory data,
        PackedUserOperation memory userOp,
        uint256 signerKey
    )
        internal
        view
        returns (bytes memory)
    {
        userOp.paymasterAndData = abi.encodePacked(
            data.paymasterAddress,
            data.preVerificationGas,
            data.postOpGas,
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
        PackedUserOperation memory userOp,
        uint256 signingKey,
        uint8 constantFeePresent,
        uint8 recipientPresent,
        uint128 preFundPresent
    )
        internal
        view
        returns (bytes memory)
    {
        userOp.paymasterAndData = abi.encodePacked(
            data.paymasterAddress,
            data.preVerificationGas,
            data.postOpGas,
            uint8((data.allowAllBundlers & 0x01) | (ERC20_MODE << 1)),
            uint8(
                (constantFeePresent == 1 ? 1 : 0) | (recipientPresent == 1 ? 1 << 1 : 0)
                    | (preFundPresent > 0 ? 1 << 2 : 0)
            )
        );

        // split into 2 parts to avoid stack too deep
        userOp.paymasterAndData = abi.encodePacked(
            userOp.paymasterAndData,
            data.validUntil,
            data.validAfter,
            erc20,
            postOpGas,
            exchangeRate,
            paymasterValidationGasLimit,
            treasury
        );

        if (preFundPresent > 0) {
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
        bytes memory sig = getSignature(hash, signingKey);

        userOp.paymasterAndData = abi.encodePacked(userOp.paymasterAndData, sig);

        return userOp.paymasterAndData;
    }

    function getSignature(bytes32 hash, uint256 signingKey) internal pure returns (bytes memory) {
        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(hash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signingKey, digest);
        return abi.encodePacked(r, s, v);
    }
}
