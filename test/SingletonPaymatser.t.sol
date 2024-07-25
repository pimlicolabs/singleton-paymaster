// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {Test, console} from "forge-std/Test.sol";
import {MessageHashUtils} from "openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol";

import {PackedUserOperation} from "account-abstraction-v7/interfaces/PackedUserOperation.sol";
import {EntryPoint} from "account-abstraction-v7/core/EntryPoint.sol";
import {SimpleAccountFactory, SimpleAccount} from "account-abstraction-v7/samples/SimpleAccountFactory.sol";

import {SingletonPaymaster} from "../src/SingletonPaymaster.sol";
import {TestERC20} from "./utils/TestERC20.sol";
import {TestCounter} from "./utils/TestCounter.sol";

contract SingletonPaymasterTest is Test {
    address payable beneficiary;
    address paymasterOwner;
    uint256 paymasterOwnerKey;
    address user;
    uint256 userKey;

    SingletonPaymaster paymaster;
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
        paymaster = new SingletonPaymaster(entryPoint, paymasterOwner);
        paymaster.deposit{value: 100e18}();
    }

    function testDeploy() external view {
        assertEq(address(paymaster.entryPoint()), address(entryPoint));
        assertEq(address(paymaster.owner()), paymasterOwner);
        assertEq(address(paymaster.treasury()), paymasterOwner);
    }

    function testOwnershipTransfer() external {
        vm.startPrank(paymasterOwner);
        assertEq(paymaster.owner(), paymasterOwner);
        paymaster.transferOwnership(beneficiary);
        assertEq(paymaster.owner(), beneficiary);
        vm.stopPrank();
    }

    function testUpdateTreasury() external {
        vm.startPrank(paymasterOwner);
        assertEq(paymaster.treasury(), paymasterOwner);
        paymaster.setTreasury(beneficiary);
        assertEq(paymaster.treasury(), beneficiary);
        vm.stopPrank();
    }

    function testAddSigner() external {
        vm.startPrank(paymasterOwner);
        assertFalse(paymaster.signers(beneficiary));
        paymaster.addSigner(beneficiary);
        assertTrue(paymaster.signers(beneficiary));
        vm.stopPrank();
    }

    function testRemoveSigner() external {
        vm.startPrank(paymasterOwner);
        assertTrue(paymaster.signers(paymasterOwner));
        paymaster.removeSigner(paymasterOwner);
        assertFalse(paymaster.signers(paymasterOwner));
        vm.stopPrank();
    }

    function testERC20PaymasterSuccess() external {
        token.sudoMint(address(account), 1000e18); // 1000 usdc;
        token.sudoMint(address(paymaster), 1); // 1000 usdc;
        token.sudoApprove(address(account), address(paymaster), UINT256_MAX);
        PackedUserOperation memory op =
            fillUserOp(account, userKey, address(counter), 0, abi.encodeWithSelector(TestCounter.count.selector));
        op.paymasterAndData = getSignedPaymasterDataErc20(op);
        op.signature = signUserOp(op, userKey);
        submitUserOp(op);
    }

    function testVerifyingPaymasterSuccess() external {
        PackedUserOperation memory op =
            fillUserOp(account, userKey, address(counter), 0, abi.encodeWithSelector(TestCounter.count.selector));
        op.paymasterAndData = getSignedPaymasterData(op);
        op.signature = signUserOp(op, userKey);
        submitUserOp(op);
    }

    // HELPERS //

    function getSignedPaymasterData(PackedUserOperation memory _userOp) private view returns (bytes memory) {
        uint48 validUntil = 0;
        uint48 validAfter = 0;
        bytes32 hash = paymaster.getHash(_userOp, validUntil, validAfter, address(0), 0);
        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(hash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(paymasterOwnerKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        return abi.encodePacked(
            address(paymaster), uint128(100000), uint128(50000), uint8(0), validUntil, validAfter, signature
        );
    }

    function getSignedPaymasterDataErc20(PackedUserOperation memory _userOp) private view returns (bytes memory) {
        uint48 validUntil = 0;
        uint48 validAfter = 0;
        uint256 price = 1;
        address erc20 = address(token);
        bytes32 hash = paymaster.getHash(_userOp, validUntil, validAfter, erc20, price);
        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(hash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(paymasterOwnerKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        return abi.encodePacked(
            address(paymaster),
            uint128(100000),
            uint128(50000),
            uint8(1),
            validUntil,
            validAfter,
            address(token),
            price,
            signature
        );
    }

    function fillUserOp(SimpleAccount _sender, uint256 _key, address _to, uint256 _value, bytes memory _data)
        private
        view
        returns (PackedUserOperation memory op)
    {
        op.sender = address(_sender);
        op.nonce = entryPoint.getNonce(address(_sender), 0);
        op.callData = abi.encodeWithSelector(SimpleAccount.execute.selector, _to, _value, _data);
        op.accountGasLimits = bytes32(abi.encodePacked(bytes16(uint128(80000)), bytes16(uint128(50000))));
        op.preVerificationGas = 50000;
        op.gasFees = bytes32(abi.encodePacked(bytes16(uint128(100)), bytes16(uint128(1000000000))));
        op.signature = signUserOp(op, _key);
        return op;
    }

    function signUserOp(PackedUserOperation memory op, uint256 _key) private view returns (bytes memory signature) {
        bytes32 hash = entryPoint.getUserOpHash(op);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_key, MessageHashUtils.toEthSignedMessageHash(hash));
        signature = abi.encodePacked(r, s, v);
    }

    function submitUserOp(PackedUserOperation memory op) private {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);
    }
}
