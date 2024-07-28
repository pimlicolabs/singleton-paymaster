// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {Test, console} from "forge-std/Test.sol";
import {MessageHashUtils} from "openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol";

import {EntryPoint} from "../src/account-abstraction/v06/core/EntryPoint.sol";
import {SimpleAccountFactory, SimpleAccount} from "../src/account-abstraction/v06/samples/SimpleAccountFactory.sol";

import {UserOperation} from "account-abstraction-v6/interfaces/UserOperation.sol";
import {IEntryPoint} from "account-abstraction-v6/interfaces/IEntryPoint.sol";

import {BaseSingletonPaymaster} from "../src/base/BaseSingletonPaymaster.sol";
import {SingletonPaymaster} from "../src/SingletonPaymaster.sol";
import {TestERC20} from "./utils/TestERC20.sol";
import {TestCounter} from "./utils/TestCounter.sol";

contract SingletonPaymasterTest is Test {
    // helpers
    uint8 immutable VERIFYING_MODE = 0;
    uint8 immutable ERC20_MODE = 1;

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
        paymaster = new SingletonPaymaster(address(entryPoint), paymasterOwner);
        paymaster.deposit{value: 100e18}();
    }

    function testSuccess(uint8 _mode) external {
        uint8 mode = uint8(bound(_mode, 0, 1));
        setupERC20();

        UserOperation memory op =
            fillUserOp(account, userKey, address(counter), 0, abi.encodeWithSelector(TestCounter.count.selector));

        op.paymasterAndData = getSignedPaymasterData(mode, op);
        op.signature = signUserOp(op, userKey);
        submitUserOp(op);
    }

    function testFailedPaymasterModeInvalid(uint8 _invalidMode) external {
        vm.assume(_invalidMode != 0 && _invalidMode != 1);
        setupERC20();

        UserOperation memory op =
            fillUserOp(account, userKey, address(counter), 0, abi.encodeWithSelector(TestCounter.count.selector));

        op.paymasterAndData = abi.encode(address(paymaster), uint128(100000), uint128(50000), _invalidMode);
        op.signature = signUserOp(op, userKey);
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA33 reverted",
                BaseSingletonPaymaster.PaymasterModeInvalid.selector
            )
        );
        submitUserOp(op);
    }

    function testFailedPaymasterConfigLengthInvalid(uint8 _mode, bytes calldata _randomBytes) external {
        uint8 mode = uint8(bound(_mode, 0, 1));
        setupERC20();

        if (mode == VERIFYING_MODE) {
            vm.assume(_randomBytes.length < 12);
        }

        if (mode == ERC20_MODE) {
            vm.assume(_randomBytes.length < 64);
        }

        UserOperation memory op =
            fillUserOp(account, userKey, address(counter), 0, abi.encodeWithSelector(TestCounter.count.selector));

        op.paymasterAndData = abi.encode(address(paymaster), uint128(100000), uint128(50000), mode, _randomBytes);
        op.signature = signUserOp(op, userKey);
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                uint256(0),
                "AA33 reverted",
                BaseSingletonPaymaster.PaymasterConfigLengthInvalid.selector
            )
        );
        submitUserOp(op);
    }

    function testFailedPaymasterSignatureLengthInvalid(uint8 _mode) external {
        uint8 mode = uint8(bound(_mode, 0, 1));
        setupERC20();

        UserOperation memory op =
            fillUserOp(account, userKey, address(counter), 0, abi.encodeWithSelector(TestCounter.count.selector));

        if (mode == VERIFYING_MODE) {
            op.paymasterAndData = abi.encode(
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
            op.paymasterAndData = abi.encode(
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
                "AA33 reverted",
                BaseSingletonPaymaster.PaymasterSignatureLengthInvalid.selector
            )
        );
        submitUserOp(op);
    }

    function testFailedTokenAddressInvalid() external {
        setupERC20();

        UserOperation memory op =
            fillUserOp(account, userKey, address(counter), 0, abi.encodeWithSelector(TestCounter.count.selector));

        op.paymasterAndData = abi.encode(
            address(paymaster),
            uint128(100000),
            uint128(50000),
            ERC20_MODE,
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
                "AA33 reverted",
                BaseSingletonPaymaster.TokenAddressInvalid.selector
            )
        );
        submitUserOp(op);
    }

    function testFailedPriceInvalid() external {
        setupERC20();

        UserOperation memory op =
            fillUserOp(account, userKey, address(counter), 0, abi.encodeWithSelector(TestCounter.count.selector));

        op.paymasterAndData = abi.encode(
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
                BaseSingletonPaymaster.TokenAddressInvalid.selector
            )
        );
        submitUserOp(op);
    }

    //function testVerifyingPaymasterSuccess() external {
    //    UserOperation memory op =
    //        fillUserOp(account, userKey, address(counter), 0, abi.encodeWithSelector(TestCounter.count.selector));
    //    op.paymasterAndData = getSignedPaymasterData(op);
    //    op.signature = signUserOp(op, userKey);
    //    submitUserOp(op);
    //}

    //function testVerifyingPaymasterFailedSignatureLengthInvalid() external {
    //    UserOperation memory op =
    //        fillUserOp(account, userKey, address(counter), 0, abi.encodeWithSelector(TestCounter.count.selector));
    //    op.paymasterAndData = abi.encode(getSignedPaymasterData(op), hex"696969");
    //    op.signature = signUserOp(op, userKey);
    //    vm.expectRevert(
    //        abi.encodeWithSelector(
    //            IEntryPoint.FailedOpWithRevert.selector,
    //            uint256(0),
    //            "AA33 reverted",
    //            abi.encodeWithSelector(BaseSingletonPaymaster.SignatureLengthInvalid.selector)
    //        )
    //    );
    //    submitUserOp(op);
    //}

    //function testVerifyingPaymasterFailedPaymasterConfigLengthInvalid() external {
    //    vm.deal(address(account), 1e18);
    //    UserOperation memory op =
    //        fillUserOp(account, userKey, address(counter), 0, abi.encodeWithSelector(TestCounter.count.selector));
    //    op.paymasterAndData = abi.encode(address(paymaster), uint128(100000), uint128(50000));
    //    op.signature = signUserOp(op, userKey);
    //    vm.expectRevert(
    //        abi.encodeWithSelector(
    //            IEntryPoint.FailedOpWithRevert.selector,
    //            uint256(0),
    //            "AA33 reverted",
    //            abi.encodeWithSelector(BaseSingletonPaymaster.SignatureLengthInvalid.selector)
    //        )
    //    );
    //    submitUserOp(op);
    //}

    // HELPERS //

    function getSignedPaymasterData(uint8 _mode, UserOperation memory _userOp) private view returns (bytes memory) {
        if (_mode == VERIFYING_MODE) {
            /* VERIFYING MODE */
            uint48 validUntil = 0;
            uint48 validAfter = 0;
            bytes32 hash = paymaster.getHash(_userOp, validUntil, validAfter, address(0), 0);
            bytes32 digest = MessageHashUtils.toEthSignedMessageHash(hash);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(paymasterOwnerKey, digest);
            bytes memory signature = abi.encode(r, s, v);

            return abi.encode(
                address(paymaster), uint128(100000), uint128(50000), uint8(0), validUntil, validAfter, signature
            );
        }
        if (_mode == ERC20_MODE) {
            /* ERC20 MODE */
            uint48 validUntil = 0;
            uint48 validAfter = 0;
            uint256 price = 1;
            address erc20 = address(token);
            bytes32 hash = paymaster.getHash(_userOp, validUntil, validAfter, erc20, price);
            bytes32 digest = MessageHashUtils.toEthSignedMessageHash(hash);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(paymasterOwnerKey, digest);
            bytes memory signature = abi.encode(r, s, v);

            return abi.encode(
                address(paymaster),
                uint128(100000),
                uint128(50000),
                uint8(1), // mode 1
                validUntil,
                validAfter,
                address(token),
                price,
                signature
            );
        }

        revert("unexpected mode");
    }

    function fillUserOp(SimpleAccount _sender, uint256 _key, address _to, uint256 _value, bytes memory _data)
        private
        view
        returns (UserOperation memory op)
    {
        op.sender = address(_sender);
        op.nonce = entryPoint.getNonce(address(_sender), 0);
        op.callData = abi.encodeWithSelector(SimpleAccount.execute.selector, _to, _value, _data);
        op.accountGasLimits = bytes32(abi.encode(bytes16(uint128(80000)), bytes16(uint128(50000))));
        op.preVerificationGas = 50000;
        op.gasFees = bytes32(abi.encode(bytes16(uint128(100)), bytes16(uint128(1000000000))));
        op.signature = signUserOp(op, _key);
        return op;
    }

    function signUserOp(UserOperation memory op, uint256 _key) private view returns (bytes memory signature) {
        bytes32 hash = entryPoint.getUserOpHash(op);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_key, MessageHashUtils.toEthSignedMessageHash(hash));
        signature = abi.encode(r, s, v);
    }

    function submitUserOp(UserOperation memory op) public {
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);
    }

    function setupERC20() private {
        token.sudoMint(address(account), 1000e18); // 1000 usdc;
        token.sudoMint(address(paymaster), 1); // 1000 usdc;
        token.sudoApprove(address(account), address(paymaster), UINT256_MAX);
    }
}
