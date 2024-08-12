//// SPDX-License-Identifier: UNLICENSED
//pragma solidity ^0.8.0;
//
//import {Test, console2} from "forge-std/Test.sol";
//import {MessageHashUtils} from "openzeppelin-contracts-v5.0.0/contracts/utils/cryptography/MessageHashUtils.sol";
//import {ERC20} from "openzeppelin-contracts-v5.0.0/contracts/token/ERC20/ERC20.sol";
//import "@openzeppelin-v4.8.0/contracts/utils/cryptography/ECDSA.sol";
//
//import {UserOperation} from "account-abstraction-v6/interfaces/UserOperation.sol";
//import {IEntryPoint} from "account-abstraction-v7/interfaces/IEntryPoint.sol";
//
//import {ERC20PostOpContext} from "../src/base/BaseSingletonPaymaster.sol";
//import {PostOpMode} from "../src/interfaces/PostOpMode.sol";
//import {BaseSingletonPaymaster} from "../src/base/BaseSingletonPaymaster.sol";
//import {SingletonPaymasterV6} from "../src/SingletonPaymasterV6.sol";
//
//import {EntryPoint} from "./utils/account-abstraction/v06/core/EntryPoint.sol";
//import {TestERC20} from "./utils/TestERC20.sol";
//import {TestCounter} from "./utils/TestCounter.sol";
//import {SimpleAccountFactory, SimpleAccount} from "./utils/account-abstraction/v06/samples/SimpleAccountFactory.sol";
//
//contract MagicSpendPlusMinusHalfTest is Test {
//    SingletonPaymasterV6 paymaster;
//    SimpleAccountFactory accountFactory;
//    SimpleAccount account;
//    EntryPoint entryPoint;
//
//    TestERC20 token;
//    TestCounter counter;
//
//    function setUp() external {
//        token = new TestERC20(18);
//        counter = new TestCounter();
//
//        beneficiary = payable(makeAddr("beneficiary"));
//        paymasterOwner = makeAddr("paymasterOwner");
//        (paymasterSigner, paymasterSignerKey) = makeAddrAndKey("paymasterSigner");
//        (user, userKey) = makeAddrAndKey("user");
//
//        entryPoint = new EntryPoint();
//        accountFactory = new SimpleAccountFactory(entryPoint);
//        account = accountFactory.createAccount(user, 0);
//
//        paymaster = new SingletonPaymasterV6(address(entryPoint), paymasterOwner);
//        paymaster.deposit{value: 100e18}();
//
//        vm.prank(paymasterOwner);
//        paymaster.addSigner(paymasterSigner);
//    }
//
//    function testDeployment() external {
//        SingletonPaymasterV6 subject = new SingletonPaymasterV6(address(entryPoint), paymasterOwner);
//        vm.prank(paymasterOwner);
//        subject.addSigner(paymasterSigner);
//
//        assertEq(subject.owner(), paymasterOwner);
//        assertEq(subject.treasury(), paymasterOwner);
//        assertTrue(subject.signers(paymasterSigner));
//    }
//
//    function testSuccess(uint8 _mode) external {
//        uint8 mode = uint8(bound(_mode, 0, 1));
//        setupERC20();
//
//        UserOperation memory op = fillUserOp();
//
//        op.paymasterAndData = getSignedPaymasterData(mode, op);
//        op.signature = signUserOp(op, userKey);
//        submitUserOp(op);
//    }
//
//    function testSuccessLegacy(uint8 _mode) external {
//        (bool success, bytes memory returnData) =
//            address(entryPoint).call(abi.encodeWithSignature("balanceOf(address)", address(paymaster)));
//        console2.log(success);
//        console2.logBytes(returnData);
//        uint8 mode = uint8(bound(_mode, 0, 1));
//        setupERC20();
//
//        UserOperation memory op = fillUserOp();
//
//        op.maxPriorityFeePerGas = 5;
//        op.maxFeePerGas = 5;
//        op.paymasterAndData = getSignedPaymasterData(mode, op);
//        op.signature = signUserOp(op, userKey);
//        submitUserOp(op);
//    }
//
//    function test_RevertWhen_PaymasterModeInvalid() external {
//        setupERC20();
//
//        UserOperation memory op = fillUserOp();
//
//        op.paymasterAndData = abi.encodePacked(address(paymaster), uint8(42));
//        op.signature = signUserOp(op, userKey);
//        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA33 reverted (or OOG)"));
//        submitUserOp(op);
//    }
//
//    function test_RevertWhen_PaymasterConfigLengthInvalid(uint8 _mode, bytes calldata _randomBytes) external {
//        uint8 mode = uint8(bound(_mode, 0, 1));
//        setupERC20();
//
//        if (mode == VERIFYING_MODE) {
//            vm.assume(_randomBytes.length < 12);
//        }
//
//        if (mode == ERC20_MODE) {
//            vm.assume(_randomBytes.length < 64);
//        }
//
//        UserOperation memory op = fillUserOp();
//
//        op.paymasterAndData = abi.encodePacked(address(paymaster), uint128(100000), uint128(50000), mode, _randomBytes);
//        op.signature = signUserOp(op, userKey);
//        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, uint256(0), "AA33 reverted (or OOG)"));
//        submitUserOp(op);
//    }
//
//    function test_RevertWhen_PaymasterSignatureLengthInvalid(uint8 _mode) external {
//        uint8 mode = uint8(bound(_mode, 0, 1));
//        setupERC20();
//
//        UserOperation memory op = fillUserOp();
//
//        if (mode == VERIFYING_MODE) {
//            op.paymasterAndData = abi.encodePacked(
//                address(paymaster),
//                uint128(100000),
//                uint128(50000),
//                mode,
//                uint48(0),
//                int48(0),
//                "BYTES WITH INVALID SIGNATURE LENGTH"
//            );
//        }
//        if (mode == ERC20_MODE) {
//            op.paymasterAndData = abi.encodePacked(
//                address(paymaster),
//                uint128(100000),
//                uint128(50000),
//                mode,
//                uint48(0),
//                int48(0),
//                address(token),
//                uint256(1),
//                "BYTES WITH INVALID SIGNATURE LENGTH"
//            );
//        }
//
//        op.signature = signUserOp(op, userKey);
//        vm.expectRevert(
//            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, uint256(0), string("AA33 reverted (or OOG)"))
//        );
//        submitUserOp(op);
//    }
//
//    // ERC20 mode specific errors
//
//    function test_PostOpTransferFromFailed() external {
//        UserOperation memory op = fillUserOp();
//
//        op.paymasterAndData = getSignedPaymasterData(1, op);
//
//        op.signature = signUserOp(op, userKey);
//        submitUserOp(op);
//    }
//
//    function test_RevertWhen_TokenAddressInvalid() external {
//        setupERC20();
//
//        UserOperation memory op = fillUserOp();
//
//        op.paymasterAndData = abi.encodePacked(
//            address(paymaster),
//            uint128(100000),
//            uint128(50000),
//            ERC20_MODE,
//            uint48(0),
//            int48(0),
//            address(0), // will throw here, token address cannot be zero.
//            uint256(1),
//            "DummySignature"
//        );
//
//        op.signature = signUserOp(op, userKey);
//        vm.expectRevert(
//            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, uint256(0), string("AA33 reverted (or OOG)"))
//        );
//        submitUserOp(op);
//    }
//
//    function test_RevertWhen_ExchangeRateInvalid() external {
//        setupERC20();
//
//        UserOperation memory op = fillUserOp();
//
//        op.paymasterAndData = abi.encodePacked(
//            address(paymaster),
//            uint128(100000),
//            uint128(50000),
//            ERC20_MODE,
//            uint48(0),
//            uint48(0),
//            address(token),
//            uint128(0),
//            uint256(0), // will throw here, price cannot be zero.
//            "DummySignature"
//        );
//
//        op.signature = signUserOp(op, userKey);
//        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, uint256(0), "AA33 reverted (or OOG)"));
//        submitUserOp(op);
//    }
//
//    function test_RevertWhen_PaymasterAndDataLengthInvalid() external {
//        setupERC20();
//
//        UserOperation memory op = fillUserOp();
//
//        op.paymasterAndData = abi.encodePacked(address(paymaster), uint128(100000), uint128(50000));
//
//        op.signature = signUserOp(op, userKey);
//        vm.expectRevert();
//        submitUserOp(op);
//    }
//
//    function test_RevertWhen_NonEntryPointCaller() external {
//        vm.expectRevert("Sender not EntryPoint");
//        paymaster.postOp(
//            PostOpMode.opSucceeded,
//            abi.encodePacked(address(account), address(token), uint256(5), bytes32(0), uint256(0), uint256(0)),
//            0
//        );
//    }
//
//    function testNoFundsSentDuringSecondPostOp() public {
//        setupERC20();
//
//        vm.startPrank(address(entryPoint));
//        paymaster.postOp(
//            PostOpMode.postOpReverted,
//            abi.encode(
//                ERC20PostOpContext({
//                    sender: user,
//                    token: address(token),
//                    postOpGas: 0,
//                    exchangeRate: uint256(0),
//                    userOpHash: bytes32(0),
//                    maxFeePerGas: uint256(0),
//                    maxPriorityFeePerGas: uint256(0)
//                })
//            ),
//            0
//        );
//        paymaster.postOp(
//            PostOpMode.opSucceeded,
//            abi.encode(
//                ERC20PostOpContext({
//                    sender: user,
//                    token: address(token),
//                    postOpGas: 0,
//                    exchangeRate: uint256(0),
//                    userOpHash: bytes32(0),
//                    maxFeePerGas: uint256(0),
//                    maxPriorityFeePerGas: uint256(0)
//                })
//            ),
//            0
//        );
//        paymaster.postOp(
//            PostOpMode.opReverted,
//            abi.encode(
//                ERC20PostOpContext({
//                    sender: user,
//                    token: address(token),
//                    postOpGas: 0,
//                    exchangeRate: uint256(0),
//                    userOpHash: bytes32(0),
//                    maxFeePerGas: uint256(0),
//                    maxPriorityFeePerGas: uint256(0)
//                })
//            ),
//            0
//        );
//    }
//
//    // HELPERS //
//
//    function getSignedPaymasterData(uint8 mode, UserOperation memory userOp) private view returns (bytes memory) {
//        PaymasterData memory data =
//            PaymasterData({paymasterAddress: address(paymaster), mode: mode, validUntil: 0, validAfter: 0});
//
//        userOp.paymasterAndData = abi.encodePacked(address(paymaster), mode);
//
//        if (mode == VERIFYING_MODE) {
//            return getVerifyingModeData(data, userOp);
//        } else if (mode == ERC20_MODE) {
//            return getERC20ModeData(data, userOp);
//        }
//
//        revert("UNEXPECTED MODE");
//    }
//
//    function getVerifyingModeData(PaymasterData memory data, UserOperation memory userOp)
//        private
//        view
//        returns (bytes memory)
//    {
//        bytes32 hash = paymaster.getHash(userOp, data.validUntil, data.validAfter);
//        bytes memory sig = getSignature(hash);
//
//        return abi.encodePacked(data.paymasterAddress, data.mode, data.validUntil, data.validAfter, sig);
//    }
//
//    function getERC20ModeData(PaymasterData memory data, UserOperation memory userOp)
//        private
//        view
//        returns (bytes memory)
//    {
//        uint256 exchangeRate = 3000 * 1e18;
//        address erc20 = address(token);
//
//        uint128 postOpGas = 50_000;
//        bytes32 hash = paymaster.getHash(userOp, data.validUntil, data.validAfter, erc20, postOpGas, exchangeRate);
//        bytes memory sig = getSignature(hash);
//
//        return abi.encodePacked(
//            data.paymasterAddress, data.mode, data.validUntil, data.validAfter, erc20, postOpGas, exchangeRate, sig
//        );
//    }
//
//    function getSignature(bytes32 hash) private view returns (bytes memory) {
//        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(hash);
//        (uint8 v, bytes32 r, bytes32 s) = vm.sign(paymasterSignerKey, digest);
//        return abi.encodePacked(r, s, v);
//    }
//
//    function fillUserOp() public view returns (UserOperation memory op) {
//        op.sender = address(account);
//        op.nonce = entryPoint.getNonce(address(account), 0);
//        op.callData = abi.encodeWithSelector(
//            SimpleAccount.execute.selector, address(counter), 0, abi.encodeWithSelector(TestCounter.count.selector)
//        );
//        op.callGasLimit = 50000;
//        op.verificationGasLimit = 180000;
//        op.preVerificationGas = 50000;
//        op.maxFeePerGas = 50;
//        op.maxPriorityFeePerGas = 15;
//        op.signature = signUserOp(op, userKey);
//        return op;
//    }
//
//    function signUserOp(UserOperation memory op, uint256 _key) public view returns (bytes memory signature) {
//        bytes32 hash = entryPoint.getUserOpHash(op);
//        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_key, hash.toEthSignedMessageHash());
//        signature = abi.encodePacked(r, s, v);
//    }
//
//    function submitUserOp(UserOperation memory op) private {
//        UserOperation[] memory ops = new UserOperation[](1);
//        ops[0] = op;
//        entryPoint.handleOps(ops, beneficiary);
//    }
//
//    function setupERC20() private {
//        token.sudoMint(address(account), 1000e18); // 1000 usdc;
//        token.sudoMint(address(paymaster), 1); // 1000 usdc;
//        token.sudoApprove(address(account), address(paymaster), UINT256_MAX);
//    }
//}
