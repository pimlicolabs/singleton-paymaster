// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Test, console2} from "forge-std/Test.sol";
import {MessageHashUtils} from "openzeppelin-contracts-v5.0.2/contracts/utils/cryptography/MessageHashUtils.sol";
import {ERC20} from "openzeppelin-contracts-v5.0.2/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin-v4.8.0/contracts/utils/cryptography/ECDSA.sol";

import {UserOperation} from "account-abstraction-v6/interfaces/UserOperation.sol";
import {IEntryPoint} from "account-abstraction-v7/interfaces/IEntryPoint.sol";

import {ERC20PostOpContext} from "../src/base/BaseSingletonPaymaster.sol";
import {PostOpMode} from "../src/interfaces/PostOpMode.sol";
import {BaseSingletonPaymaster} from "../src/base/BaseSingletonPaymaster.sol";
import {SingletonPaymasterV6} from "../src/SingletonPaymasterV6.sol";

import {EntryPoint} from "./utils/account-abstraction/v06/core/EntryPoint.sol";
import {TestERC20} from "./utils/TestERC20.sol";
import {TestCounter} from "./utils/TestCounter.sol";
import {SimpleAccountFactory, SimpleAccount} from "./utils/account-abstraction/v06/samples/SimpleAccountFactory.sol";

using ECDSA for bytes32;

struct SignatureData {
    uint8 v;
    bytes32 r;
    bytes32 s;
}

struct PaymasterData {
    address paymasterAddress;
    uint8 mode;
    uint48 validUntil;
    uint48 validAfter;
}

contract SingletonPaymasterV6Test is Test {
    uint8 immutable VERIFYING_MODE = 0;
    uint8 immutable ERC20_MODE = 1;
    uint256 immutable EXCHANGE_RATE = 3000 * 1e18;

    address payable beneficiary;
    address paymasterOwner;
    address paymasterSigner;
    uint256 paymasterSignerKey;
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
        (paymasterSigner, paymasterSignerKey) = makeAddrAndKey("paymasterSigner");
        (user, userKey) = makeAddrAndKey("user");

        entryPoint = new EntryPoint();
        accountFactory = new SimpleAccountFactory(entryPoint);
        account = accountFactory.createAccount(user, 0);

        paymaster = new SingletonPaymasterV6(address(entryPoint), paymasterOwner);
        paymaster.deposit{value: 100e18}();

        vm.prank(paymasterOwner);
        paymaster.addSigner(paymasterSigner);
    }

    function testDeployment() external {
        SingletonPaymasterV6 subject = new SingletonPaymasterV6(address(entryPoint), paymasterOwner);
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

        UserOperation memory op = fillUserOp();
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
        UserOperation memory op = fillUserOp();
        op.paymasterAndData = getSignedPaymasterData(VERIFYING_MODE, op);
        op.signature = signUserOp(op, userKey);

        // check that UserOperationSponsored log is emitted.
        vm.expectEmit(address(paymaster));
        emit BaseSingletonPaymaster.UserOperationSponsored(getOpHash(op), op.sender, VERIFYING_MODE, address(0), 0, 0);

        submitUserOp(op);
    }

    function test_RevertWhen_ERC20PaymasterSignatureInvalid() external {
        UserOperation memory op = fillUserOp();

        uint48 validUntil = 0;
        uint48 validAfter = 0;
        address erc20 = address(token);
        uint128 postOpGas = 50_000;

        // sign with random private key to force false signature
        (, uint256 unauthorizedSignerKey) = makeAddrAndKey("unauthorizedSigner");
        op.paymasterAndData = abi.encodePacked(address(paymaster), uint128(0), uint128(0), VERIFYING_MODE);
        bytes32 hash = paymaster.getHash(op, validUntil, validAfter, erc20, postOpGas, EXCHANGE_RATE);
        bytes memory sig = getSignature(hash, unauthorizedSignerKey);

        op.paymasterAndData = abi.encodePacked(
            address(paymaster),
            ERC20_MODE,
            validUntil, // validUntil
            validAfter, // validAfter
            erc20,
            postOpGas, // token postOp gas
            EXCHANGE_RATE,
            sig
        );
        op.signature = signUserOp(op, userKey);

        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, uint256(0), "AA34 signature error"));
        submitUserOp(op);
    }

    function test_RevertWhen_VerifyingPaymasterSignatureInvalid() external {
        UserOperation memory op = fillUserOp();

        uint48 validUntil = 0;
        uint48 validAfter = 0;

        // sign with random private key to force false signature
        (, uint256 unauthorizedSignerKey) = makeAddrAndKey("unauthorizedSigner");
        op.paymasterAndData = abi.encodePacked(address(paymaster), uint128(0), uint128(0), VERIFYING_MODE);
        bytes32 hash = paymaster.getHash(op, validUntil, validAfter);
        bytes memory sig = getSignature(hash, unauthorizedSignerKey);

        op.paymasterAndData = abi.encodePacked(address(paymaster), VERIFYING_MODE, validUntil, validAfter, sig);
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

    function test_RevertWhen_PaymasterModeInvalid(uint8 invalidMode) external {
        vm.assume(invalidMode != ERC20_MODE && invalidMode != VERIFYING_MODE);

        UserOperation memory op = fillUserOp();

        op.paymasterAndData = abi.encodePacked(address(paymaster), invalidMode);
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

        op.paymasterAndData = abi.encodePacked(address(paymaster), uint128(100000), uint128(50000), mode, _randomBytes);
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
                uint128(100000),
                uint128(50000),
                mode,
                uint48(0),
                int48(0),
                "BYTES WITH INVALID SIGNATURE LENGTH"
            );
        }

        if (mode == ERC20_MODE) {
            op.paymasterAndData = abi.encodePacked(
                address(paymaster),
                uint128(100000),
                uint128(50000),
                mode,
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

        op.paymasterAndData = getSignedPaymasterData(ERC20_MODE, op);
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
            uint48(0), // validUntil
            int48(0), // validAfter
            address(0), // **will throw here, token address cannot be zero.**
            uint128(1), // postOpGas
            uint256(1), // exchangeRate
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
        op.paymasterAndData = abi.encodePacked(address(paymaster), uint128(100000), uint128(50000));
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

    // HELPERS //

    function getSignedPaymasterData(uint8 mode, UserOperation memory userOp) private view returns (bytes memory) {
        PaymasterData memory data =
            PaymasterData({paymasterAddress: address(paymaster), mode: mode, validUntil: 0, validAfter: 0});

        // set paymasterAndData here so that correct hash is calculated.
        userOp.paymasterAndData = abi.encodePacked(address(paymaster), mode);

        if (mode == VERIFYING_MODE) {
            return getVerifyingModeData(data, userOp);
        } else if (mode == ERC20_MODE) {
            return getERC20ModeData(data, userOp);
        }

        revert("UNEXPECTED MODE");
    }

    function getVerifyingModeData(PaymasterData memory data, UserOperation memory userOp)
        private
        view
        returns (bytes memory)
    {
        bytes32 hash = paymaster.getHash(userOp, data.validUntil, data.validAfter);
        bytes memory sig = getSignature(hash, paymasterSignerKey);

        return abi.encodePacked(data.paymasterAddress, data.mode, data.validUntil, data.validAfter, sig);
    }

    function getERC20ModeData(PaymasterData memory data, UserOperation memory userOp)
        private
        view
        returns (bytes memory)
    {
        address erc20 = address(token);

        uint128 postOpGas = 50_000;
        bytes32 hash = paymaster.getHash(userOp, data.validUntil, data.validAfter, erc20, postOpGas, EXCHANGE_RATE);
        bytes memory sig = getSignature(hash, paymasterSignerKey);

        return abi.encodePacked(
            data.paymasterAddress, data.mode, data.validUntil, data.validAfter, erc20, postOpGas, EXCHANGE_RATE, sig
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
        op.callGasLimit = 50000;
        op.verificationGasLimit = 180000;
        op.preVerificationGas = 50000;
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
