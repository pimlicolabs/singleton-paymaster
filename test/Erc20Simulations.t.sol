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

import { Erc20PaymasterSimulationsV6 } from "../src/misc/Erc20Simulations.sol";

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
}

contract SingletonPaymasterV6Test is Test {
    uint8 immutable VERIFYING_MODE = 0;
    uint8 immutable ALLOW_ALL_BUNDLERS = 1;
    uint8 immutable ERC20_MODE = 1;
    uint256 immutable EXCHANGE_RATE = 3000 * 1e18;
    uint128 immutable POSTOP_GAS = 50_000;

    address payable beneficiary;
    address paymasterOwner;
    address paymasterSigner;
    address treasury;
    address manager;
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

    function testSimulate() external {
        setupERC20Environment();

        // treasury should have no tokens
        assertEq(token.balanceOf(treasury), 0);

        UserOperation memory op = fillUserOp();
        op.paymasterAndData = getSignedPaymasterData(ERC20_MODE, op);
        op.signature = signUserOp(op, userKey);

        new Erc20PaymasterSimulationsV6(token, op, address(entryPoint), treasury);
    }

    function getSignedPaymasterData(uint8 mode, UserOperation memory userOp) private view returns (bytes memory) {
        PaymasterData memory data =
            PaymasterData({ paymasterAddress: address(paymaster), validUntil: 0, validAfter: 0 });

        if (mode == VERIFYING_MODE) {
            return getVerifyingModeData(data, userOp, paymasterSignerKey);
        } else if (mode == ERC20_MODE) {
            return
                getERC20ModeData(
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
            address(paymaster),
            uint8((ALLOW_ALL_BUNDLERS & 0x01) | (VERIFYING_MODE << 1)),
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
        uint256 signerKey
    )
        private
        view
        returns (bytes memory)
    {
        uint8 constantFeePresent = uint8(0);
        uint8 recipientPresent = uint8(0);

        userOp.paymasterAndData = abi.encodePacked(
            data.paymasterAddress,
            uint8((ALLOW_ALL_BUNDLERS & 0x01) | (ERC20_MODE << 1)),
            uint8((constantFeePresent & 0x01) | (recipientPresent << 1)),
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

        return abi.encodePacked(userOp.paymasterAndData, sig);
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
