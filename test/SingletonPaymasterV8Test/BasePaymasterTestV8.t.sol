// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { Test, console } from "forge-std/Test.sol";
import { MessageHashUtils } from "openzeppelin-contracts-v5.0.2/contracts/utils/cryptography/MessageHashUtils.sol";
import { IERC20 } from "openzeppelin-contracts-v5.0.2/contracts/token/ERC20/IERC20.sol";

import { IEntryPoint } from "@account-abstraction-v8/interfaces/IEntryPoint.sol";
import { PackedUserOperation } from "account-abstraction-v7/interfaces/PackedUserOperation.sol";
import { PackedUserOperation as PackedUserOperationV8 } from "account-abstraction-v8/interfaces/PackedUserOperation.sol";
import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";

import { ERC20PostOpContext, BaseSingletonPaymaster } from "../../src/base/BaseSingletonPaymaster.sol";
import { SingletonPaymasterV8 } from "../../src/SingletonPaymasterV8.sol";
import { PostOpMode } from "../../src/interfaces/PostOpMode.sol";

import { SimpleAccountFactory, SimpleAccount } from "@account-abstraction-v8/accounts/SimpleAccountFactory.sol";
import { EntryPoint } from "@account-abstraction-v8/core/EntryPoint.sol";
import { BaseAccount } from "@account-abstraction-v8/core/BaseAccount.sol";
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

        entryPoint = new EntryPoint();
        
        // Account creation is done in child contracts
        
        paymaster = new SingletonPaymasterV8(address(entryPoint), paymasterOwner, manager, new address[](0));
        paymaster.deposit{ value: 100e18 }();

        vm.prank(paymasterOwner);
        paymaster.addSigner(paymasterSigner);
    }
    
    // Shared test methods
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
    ) internal view returns (bytes memory) {
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
    ) internal view returns (bytes memory) {
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
    ) internal view returns (bytes memory) {
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