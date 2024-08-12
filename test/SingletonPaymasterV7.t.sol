// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Test, console} from "forge-std/Test.sol";
import {MessageHashUtils} from "openzeppelin-contracts-v5.0.0/contracts/utils/cryptography/MessageHashUtils.sol";
import {IERC20} from "openzeppelin-contracts-v5.0.0/contracts/token/ERC20/IERC20.sol";

import {IEntryPoint} from "@account-abstraction-v7/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction-v7/interfaces/PackedUserOperation.sol";
import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";

import {BaseSingletonPaymaster} from "../src/base/BaseSingletonPaymaster.sol";
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
    uint8 mode;
    uint48 validUntil;
    uint48 validAfter;
}

contract SingletonPaymasterV7Test is Test {
    // helpers
    uint8 immutable VERIFYING_MODE = 0;
    uint8 immutable ERC20_MODE = 1;
    uint256 immutable EXCHANGE_RATE = 3000 * 1e18;

    address payable beneficiary;
    address paymasterOwner;
    address paymasterSigner;
    uint256 paymasterSignerKey;
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
        (user, userKey) = makeAddrAndKey("user");

        entryPoint = new EntryPoint();
        accountFactory = new SimpleAccountFactory(entryPoint);
        account = accountFactory.createAccount(user, 0);

        paymaster = new SingletonPaymasterV7(address(entryPoint), paymasterOwner);
        paymaster.deposit{value: 100e18}();

        vm.prank(paymasterOwner);
        paymaster.addSigner(paymasterSigner);
    }

    function testDeployment() external {
        SingletonPaymasterV7 subject = new SingletonPaymasterV7(address(entryPoint), paymasterOwner);
        vm.prank(paymasterOwner);
        subject.addSigner(paymasterSigner);

        assertEq(subject.owner(), paymasterOwner);
        assertEq(subject.treasury(), paymasterOwner);
        assertTrue(subject.signers(paymasterSigner));
    }

    function testERC20Success() external {
        setupERC20Environment();

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
            vm.assume(_randomBytes.length < 64);
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

    function test_RevetWhen_PaymasterSignatureLengthInvalid(uint8 _mode) external {
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
            uint128(0), // fund amount
            uint48(0),
            int48(0),
            address(0), // will throw here, token address cannot be zero.
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

    // HELPERS //

    function getSignedPaymasterData(uint8 mode, PackedUserOperation memory userOp)
        private
        view
        returns (bytes memory)
    {
        PaymasterData memory data = PaymasterData({
            paymasterAddress: address(paymaster),
            preVerificationGas: 100_000,
            postOpGas: 50_000,
            mode: mode,
            validUntil: 0,
            validAfter: 0
        });

        userOp.paymasterAndData = abi.encodePacked(data.paymasterAddress, data.preVerificationGas, data.postOpGas, mode);

        if (mode == VERIFYING_MODE) {
            return getVerifyingModeData(data, userOp);
        } else if (mode == ERC20_MODE) {
            return getERC20ModeData(data, userOp);
        }

        revert("unexpected mode");
    }

    function getVerifyingModeData(PaymasterData memory data, PackedUserOperation memory userOp)
        private
        view
        returns (bytes memory)
    {
        bytes32 hash = paymaster.getHash(userOp, data.validUntil, data.validAfter);
        bytes memory sig = getSignature(hash);

        return abi.encodePacked(
            data.paymasterAddress,
            data.preVerificationGas,
            data.postOpGas,
            data.mode,
            data.validUntil,
            data.validAfter,
            sig
        );
    }

    function getERC20ModeData(PaymasterData memory data, PackedUserOperation memory userOp)
        private
        view
        returns (bytes memory)
    {
        uint256 exchangeRate = 0.0016 * 1e18;
        address erc20 = address(token);

        uint128 postOpGas = 50_000;
        bytes32 hash = paymaster.getHash(userOp, data.validUntil, data.validAfter, erc20, postOpGas, exchangeRate);
        bytes memory sig = getSignature(hash);

        return abi.encodePacked(
            data.paymasterAddress,
            data.preVerificationGas,
            data.postOpGas,
            data.mode,
            data.validUntil,
            data.validAfter,
            erc20,
            postOpGas,
            exchangeRate,
            sig
        );
    }

    function getSignature(bytes32 hash) private view returns (bytes memory) {
        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(hash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(paymasterSignerKey, digest);
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
        token.sudoMint(address(account), 1000e18); // 1000 usdc;
        token.sudoMint(address(paymaster), 1); // 1000 usdc;
        token.sudoApprove(address(account), address(paymaster), UINT256_MAX);
    }
}
