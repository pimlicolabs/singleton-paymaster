// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {Test, console} from "forge-std/Test.sol";
import {MessageHashUtils} from "openzeppelin-contracts-v5.0.0/contracts/utils/cryptography/MessageHashUtils.sol";

import {IEntryPoint} from "@account-abstraction-v7/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction-v7/interfaces/PackedUserOperation.sol";

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
    uint128 fundAmount;
    uint48 validUntil;
    uint48 validAfter;
}

contract SingletonPaymasterV7Test is Test {
    // helpers
    uint8 immutable VERIFYING_MODE = 0;
    uint8 immutable ERC20_MODE = 1;

    address payable beneficiary;
    address paymasterOwner;
    uint256 paymasterOwnerKey;
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
        (paymasterOwner, paymasterOwnerKey) = makeAddrAndKey("paymasterOperator");
        (user, userKey) = makeAddrAndKey("user");

        entryPoint = new EntryPoint();
        accountFactory = new SimpleAccountFactory(entryPoint);
        account = accountFactory.createAccount(user, 0);

        paymaster = new SingletonPaymasterV7(address(entryPoint), paymasterOwner);
        paymaster.deposit{value: 100e18}();
    }

    function testSuccess(uint8 _mode) external {
        uint8 mode = uint8(bound(_mode, 0, 1));
        setupERC20();

        PackedUserOperation memory op = fillUserOp();

        op.paymasterAndData = getSignedPaymasterData(mode, 0, op);
        op.signature = signUserOp(op, userKey);
        submitUserOp(op);
    }

    function test_RevertWhen_PaymasterModeInvalid(uint8 _invalidMode) external {
        vm.assume(_invalidMode != 0 && _invalidMode != 1);
        setupERC20();

        PackedUserOperation memory op = fillUserOp();

        op.paymasterAndData =
            abi.encodePacked(address(paymaster), uint128(100000), uint128(50000), _invalidMode, uint128(0));
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
        setupERC20();

        if (mode == VERIFYING_MODE) {
            vm.assume(_randomBytes.length < 24);
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
        setupERC20();

        PackedUserOperation memory op = fillUserOp();

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
        setupERC20();

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
        setupERC20();

        PackedUserOperation memory op = fillUserOp();

        op.paymasterAndData = abi.encodePacked(
            address(paymaster),
            uint128(100000),
            uint128(50000),
            ERC20_MODE,
            uint48(0),
            int48(0),
            address(token),
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
        setupERC20();

        PackedUserOperation memory op = fillUserOp();

        op.paymasterAndData = abi.encodePacked(address(paymaster), uint128(100000), uint128(50000));

        op.signature = signUserOp(op, userKey);
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                uint256(0),
                "AA33 reverted",
                abi.encodeWithSelector(BaseSingletonPaymaster.PaymasterDataLengthInvalid.selector)
            )
        );
        submitUserOp(op);
    }

    function test_PostOpTransferFromFailed() external {
        PackedUserOperation memory op = fillUserOp();

        op.paymasterAndData = getSignedPaymasterData(1, 0, op);

        op.signature = signUserOp(op, userKey);
        submitUserOp(op);
    }

    function test_RevertWhen_NonEntryPointCaller() external {
        vm.expectRevert("Sender not EntryPoint");
        paymaster.postOp(PostOpMode.opSucceeded, "", 0, 0);
    }

    // HELPERS //

    function getSignedPaymasterData(uint8 mode, uint128 fundAmount, PackedUserOperation memory userOp)
        private
        view
        returns (bytes memory)
    {
        PaymasterData memory data = PaymasterData({
            paymasterAddress: address(paymaster),
            preVerificationGas: 100000,
            postOpGas: 50000,
            mode: mode,
            fundAmount: fundAmount,
            validUntil: 0,
            validAfter: 0
        });

        userOp.paymasterAndData = abi.encodePacked(data.paymasterAddress, data.preVerificationGas, data.postOpGas);

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
        bytes32 hash = paymaster.getHash(userOp, data.validUntil, data.validAfter, address(0), 0, data.fundAmount);
        bytes memory sig = getSignature(hash);

        console.log("real signature");
        console.logBytes(sig);

        return abi.encodePacked(
            data.paymasterAddress,
            data.preVerificationGas,
            data.postOpGas,
            data.mode,
            data.validUntil,
            data.validAfter,
            data.fundAmount,
            sig
        );
    }

    function getERC20ModeData(PaymasterData memory data, PackedUserOperation memory userOp)
        private
        view
        returns (bytes memory)
    {
        uint256 price = 0.0016 * 1e18;
        address erc20 = address(token);
        bytes32 hash = paymaster.getHash(userOp, data.validUntil, data.validAfter, erc20, price, 0);
        bytes memory sig = getSignature(hash);

        console.log("real signature");
        console.logBytes(sig);

        return abi.encodePacked(
            data.paymasterAddress,
            data.preVerificationGas,
            data.postOpGas,
            data.mode,
            data.validUntil,
            data.validAfter,
            erc20,
            price,
            sig
        );
    }

    function getSignature(bytes32 hash) private view returns (bytes memory) {
        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(hash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(paymasterOwnerKey, digest);
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

    function setupERC20() private {
        token.sudoMint(address(account), 1000e18); // 1000 usdc;
        token.sudoMint(address(paymaster), 1); // 1000 usdc;
        token.sudoApprove(address(account), address(paymaster), UINT256_MAX);
    }
}
