// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import { PackedUserOperation } from "@account-abstraction-v7/interfaces/PackedUserOperation.sol";
import { _packValidationData } from "@account-abstraction-v7/core/Helpers.sol";
import { UserOperationLib } from "@account-abstraction-v7/core/UserOperationLib.sol";

import { ECDSA } from "@openzeppelin-v5.0.2/contracts/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from "@openzeppelin-v5.0.2/contracts/utils/cryptography/MessageHashUtils.sol";

import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";

import { BaseSingletonPaymaster, ERC20PaymasterData, ERC20PostOpContext } from "./base/BaseSingletonPaymaster.sol";
import { IPaymasterV7 } from "./interfaces/IPaymasterV7.sol";
import { PostOpMode } from "./interfaces/PostOpMode.sol";

using UserOperationLib for PackedUserOperation;

/// @title SingletonPaymasterV7
/// @author Pimlico (https://github.com/pimlicolabs/singleton-paymaster/blob/main/src/SingletonPaymasterV7.sol)
/// @author Using Solady (https://github.com/vectorized/solady)
/// @notice An ERC-4337 Paymaster contract which supports two modes, Verifying and ERC-20.
/// In ERC-20 mode, the paymaster sponsors a UserOperation in exchange for tokens.
/// In Verifying mode, the paymaster sponsors a UserOperation and deducts prepaid balance from the user's Pimlico
/// balance.
/// @dev Inherits from BaseSingletonPaymaster.
/// @custom:security-contact security@pimlico.io
contract SingletonPaymasterV7 is BaseSingletonPaymaster, IPaymasterV7 {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  CONSTANTS AND IMMUTABLES                  */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    uint256 private immutable PAYMASTER_DATA_OFFSET = UserOperationLib.PAYMASTER_DATA_OFFSET;
    uint256 private immutable PAYMASTER_VALIDATION_GAS_OFFSET = UserOperationLib.PAYMASTER_VALIDATION_GAS_OFFSET;
    uint256 private constant PENALTY_PERCENT = 10;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        CONSTRUCTOR                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    constructor(
        address _entryPoint,
        address _owner,
        address _manager,
        address[] memory _signers
    )
        BaseSingletonPaymaster(_entryPoint, _owner, _manager, _signers)
    { }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*        ENTRYPOINT V0.7 ERC-4337 PAYMASTER OVERRIDES        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @inheritdoc IPaymasterV7
    function validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 requiredPreFund
    )
        external
        override
        returns (bytes memory context, uint256 validationData)
    {
        _requireFromEntryPoint();
        return _validatePaymasterUserOp(userOp, userOpHash, requiredPreFund);
    }

    /// @inheritdoc IPaymasterV7
    function postOp(
        PostOpMode mode,
        bytes calldata context,
        uint256 actualGasCost,
        uint256 actualUserOpFeePerGas
    )
        external
        override
    {
        _requireFromEntryPoint();
        _postOp(mode, context, actualGasCost, actualUserOpFeePerGas);
    }

    /**
     * @notice Internal helper to parse and validate the userOperation's paymasterAndData.
     * @param _userOp The userOperation.
     * @param _userOpHash The userOperation hash.
     * @return (context, validationData) The context and validation data to return to the EntryPoint.
     *
     * @dev paymasterAndData for mode 0:
     * - paymaster address (20 bytes)
     * - paymaster verification gas (16 bytes)
     * - paymaster postop gas (16 bytes)
     * - mode and allowAllBundlers (1 byte) - lowest bit represents allowAllBundlers, rest of the bits represent mode
     * - validUntil (6 bytes)
     * - validAfter (6 bytes)
     * - signature (64 or 65 bytes)
     *
     * @dev paymasterAndData for mode 1:
     * - paymaster address (20 bytes)
     * - paymaster verification gas (16 bytes)
     * - paymaster postop gas (16 bytes)
     * - mode and allowAllBundlers (1 byte) - lowest bit represents allowAllBundlers, rest of the bits represent mode
     * - constantFeePresent and recipientPresent and preFundPresent (1 byte) - 00000{preFundPresent
     * bit}{recipientPresent bit}{constantFeePresent bit}
     * - validUntil (6 bytes)
     * - validAfter (6 bytes)
     * - token address (20 bytes)
     * - postOpGas (16 bytes)
     * - exchangeRate (32 bytes)
     * - paymasterValidationGasLimit (16 bytes)
     * - treasury (20 bytes)
     * - preFund (16 bytes) - only if preFundPresent is 1
     * - constantFee (16 bytes - only if constantFeePresent is 1)
     * - recipient (20 bytes - only if recipientPresent is 1)
     * - signature (64 or 65 bytes)
     *
     *
     */
    function _validatePaymasterUserOp(
        PackedUserOperation calldata _userOp,
        bytes32 _userOpHash,
        uint256 _requiredPreFund
    )
        internal
        returns (bytes memory, uint256)
    {
        (uint8 mode, bool allowAllBundlers, bytes calldata paymasterConfig) =
            _parsePaymasterAndData(_userOp.paymasterAndData, PAYMASTER_DATA_OFFSET);

        if (!allowAllBundlers && !isBundlerAllowed[tx.origin]) {
            revert BundlerNotAllowed(tx.origin);
        }

        if (mode != ERC20_MODE && mode != VERIFYING_MODE) {
            revert PaymasterModeInvalid();
        }

        bytes memory context;
        uint256 validationData;

        if (mode == VERIFYING_MODE) {
            (context, validationData) = _validateVerifyingMode(_userOp, paymasterConfig, _userOpHash);
        }

        if (mode == ERC20_MODE) {
            (context, validationData) =
                _validateERC20Mode(mode, _userOp, paymasterConfig, _userOpHash, _requiredPreFund);
        }

        return (context, validationData);
    }

    /**
     * @notice Internal helper to validate the paymasterAndData when used in verifying mode.
     * @param _userOp The userOperation.
     * @param _paymasterConfig The encoded paymaster config taken from paymasterAndData.
     * @param _userOpHash The userOperation hash.
     * @return (context, validationData) The validation data to return to the EntryPoint.
     */
    function _validateVerifyingMode(
        PackedUserOperation calldata _userOp,
        bytes calldata _paymasterConfig,
        bytes32 _userOpHash
    )
        internal
        returns (bytes memory, uint256)
    {
        (uint48 validUntil, uint48 validAfter, bytes calldata signature) = _parseVerifyingConfig(_paymasterConfig);

        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(getHash(VERIFYING_MODE, _userOp));
        address recoveredSigner = ECDSA.recover(hash, signature);

        bool isSignatureValid = signers[recoveredSigner];
        uint256 validationData = _packValidationData(!isSignatureValid, validUntil, validAfter);

        emit UserOperationSponsored(_userOpHash, _userOp.getSender(), VERIFYING_MODE, address(0), 0, 0);
        return ("", validationData);
    }

    /**
     * @notice Internal helper to validate the paymasterAndData when used in ERC-20 mode.
     * @param _userOp The userOperation.
     * @param _paymasterConfig The encoded paymaster config taken from paymasterAndData.
     * @param _userOpHash The userOperation hash.
     * @return (context, validationData) The validation data to return to the EntryPoint.
     */
    function _validateERC20Mode(
        uint8 _mode,
        PackedUserOperation calldata _userOp,
        bytes calldata _paymasterConfig,
        bytes32 _userOpHash,
        uint256 _requiredPreFund
    )
        internal
        returns (bytes memory, uint256)
    {
        ERC20PaymasterData memory cfg = _parseErc20Config(_paymasterConfig);

        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(getHash(_mode, _userOp));
        address recoveredSigner = ECDSA.recover(hash, cfg.signature);

        bool isSignatureValid = signers[recoveredSigner];
        uint256 validationData = _packValidationData(!isSignatureValid, cfg.validUntil, cfg.validAfter);
        bytes memory context = _createPostOpContext(_userOp, _userOpHash, cfg, _requiredPreFund);

        if (!isSignatureValid) {
            return (context, validationData);
        }

        uint256 costInToken = getCostInToken(_requiredPreFund, 0, 0, cfg.exchangeRate);

        if (cfg.preFundInToken > costInToken) {
            revert PreFundTooHigh();
        }

        if (cfg.preFundInToken > 0) {
            SafeTransferLib.safeTransferFrom(cfg.token, _userOp.sender, cfg.treasury, cfg.preFundInToken);
        }

        return (context, validationData);
    }

    function _expectedPenaltyGasCost(
        uint256 _actualGasCost,
        uint256 _actualUserOpFeePerGas,
        uint128 postOpGas,
        uint256 preOpGasApproximation,
        uint256 executionGasLimit
    )
        public
        pure
        virtual
        returns (uint256)
    {
        uint256 executionGasUsed = 0;
        uint256 actualGas = _actualGasCost / _actualUserOpFeePerGas + postOpGas;

        if (actualGas > preOpGasApproximation) {
            executionGasUsed = actualGas - preOpGasApproximation;
        }

        uint256 expectedPenaltyGas = 0;
        if (executionGasLimit > executionGasUsed) {
            expectedPenaltyGas = ((executionGasLimit - executionGasUsed) * PENALTY_PERCENT) / 100;
        }

        return expectedPenaltyGas * _actualUserOpFeePerGas;
    }

    /**
     * @notice Handles ERC-20 token payment.
     * @dev PostOp is skipped in verifying mode because paymaster's postOp isn't called when context is empty.
     * @param _context The encoded ERC-20 paymaster context.
     * @param _actualGasCost The totla gas cost (in wei) of this userOperation.
     * @param _actualUserOpFeePerGas The actual gas price of the userOperation.
     */
    function _postOp(
        PostOpMode, /* mode */
        bytes calldata _context,
        uint256 _actualGasCost,
        uint256 _actualUserOpFeePerGas
    )
        internal
    {
        ERC20PostOpContext memory ctx = _parsePostOpContext(_context);

        uint256 expectedPenaltyGasCost = _expectedPenaltyGasCost(
            _actualGasCost, _actualUserOpFeePerGas, ctx.postOpGas, ctx.preOpGasApproximation, ctx.executionGasLimit
        );

        uint256 actualGasCost = _actualGasCost + expectedPenaltyGasCost;

        uint256 costInToken =
            getCostInToken(actualGasCost, ctx.postOpGas, _actualUserOpFeePerGas, ctx.exchangeRate) + ctx.constantFee;

        uint256 absoluteCostInToken =
            costInToken > ctx.preFundCharged ? costInToken - ctx.preFundCharged : ctx.preFundCharged - costInToken;

        SafeTransferLib.safeTransferFrom(
            ctx.token,
            costInToken > ctx.preFundCharged ? ctx.sender : ctx.treasury,
            costInToken > ctx.preFundCharged ? ctx.treasury : ctx.sender,
            absoluteCostInToken
        );

        uint256 preFundInToken = (ctx.preFund * ctx.exchangeRate) / 1e18;

        if (ctx.recipient != address(0) && preFundInToken > costInToken) {
            SafeTransferLib.safeTransferFrom(ctx.token, ctx.sender, ctx.recipient, preFundInToken - costInToken);
        }

        emit UserOperationSponsored(ctx.userOpHash, ctx.sender, ERC20_MODE, ctx.token, costInToken, ctx.exchangeRate);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PUBLIC HELPERS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @notice Hashses the userOperation data when used in ERC-20 mode.
     * @param _userOp The user operation data.
     * @param _mode The mode that we want to get the hash for.
     * @return bytes32 The hash that the signer should sign over.
     */
    function getHash(uint8 _mode, PackedUserOperation calldata _userOp) public view virtual returns (bytes32) {
        if (_mode == VERIFYING_MODE) {
            return _getHash(_userOp, MODE_AND_ALLOW_ALL_BUNDLERS_LENGTH + VERIFYING_PAYMASTER_DATA_LENGTH);
        } else {
            uint8 paymasterDataLength = MODE_AND_ALLOW_ALL_BUNDLERS_LENGTH + ERC20_PAYMASTER_DATA_LENGTH;

            uint8 combinedByte =
                uint8(_userOp.paymasterAndData[PAYMASTER_DATA_OFFSET + MODE_AND_ALLOW_ALL_BUNDLERS_LENGTH]);
            // constantFeePresent is in the *lowest* bit
            bool constantFeePresent = (combinedByte & 0x01) != 0;
            // recipientPresent is in the second lowest bit
            bool recipientPresent = (combinedByte & 0x02) != 0;
            // preFundPresent is in the third lowest bit
            bool preFundPresent = (combinedByte & 0x04) != 0;

            if (preFundPresent) {
                paymasterDataLength += 16;
            }

            if (constantFeePresent) {
                paymasterDataLength += 16;
            }

            if (recipientPresent) {
                paymasterDataLength += 20;
            }

            return _getHash(_userOp, paymasterDataLength);
        }
    }

    /**
     * @notice Internal helper that hashes the user operation data.
     * @dev We hash over all fields in paymasterAndData but the paymaster signature.
     * @param paymasterDataLength The paymasterData length.
     * @return bytes32 The hash that the signer should sign over.
     */
    function _getHash(
        PackedUserOperation calldata _userOp,
        uint256 paymasterDataLength
    )
        internal
        view
        returns (bytes32)
    {
        bytes32 userOpHash = keccak256(
            abi.encode(
                _userOp.getSender(),
                _userOp.nonce,
                _userOp.accountGasLimits,
                _userOp.preVerificationGas,
                _userOp.gasFees,
                keccak256(_userOp.initCode),
                keccak256(_userOp.callData),
                // hashing over all paymaster fields besides signature
                keccak256(_userOp.paymasterAndData[:PAYMASTER_DATA_OFFSET + paymasterDataLength])
            )
        );

        return keccak256(abi.encode(userOpHash, block.chainid));
    }
}
