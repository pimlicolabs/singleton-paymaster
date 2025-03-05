// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import { UserOperation } from "@account-abstraction-v6/interfaces/IPaymaster.sol";
import { _packValidationData } from "@account-abstraction-v6/core/Helpers.sol";

import { ECDSA } from "@openzeppelin-v5.0.2/contracts/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from "@openzeppelin-v5.0.2/contracts/utils/cryptography/MessageHashUtils.sol";
import { Math } from "@openzeppelin-v5.0.2/contracts/utils/math/Math.sol";

import { BaseSingletonPaymaster, ERC20PaymasterData, ERC20PostOpContext } from "./base/BaseSingletonPaymaster.sol";
import { IPaymasterV6 } from "./interfaces/IPaymasterV6.sol";
import { PostOpMode } from "./interfaces/PostOpMode.sol";

import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";

/// @title SingletonPaymasterV6
/// @author Pimlico (https://github.com/pimlicolabs/singleton-paymaster/blob/main/src/SingletonPaymasterV6.sol)
/// @author Using Solady (https://github.com/vectorized/solady)
/// @notice An ERC-4337 Paymaster contract which supports two modes, Verifying and ERC-20.
/// In ERC-20 mode, the paymaster sponsors a UserOperation in exchange for tokens.
/// In Verifying mode, the paymaster sponsors a UserOperation from the user's Pimlico balance.
/// @dev Inherits from BaseSingletonPaymaster.
/// @custom:security-contact security@pimlico.io
contract SingletonPaymasterV6 is BaseSingletonPaymaster, IPaymasterV6 {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  CONSTANTS AND IMMUTABLES                  */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    uint256 private immutable PAYMASTER_DATA_OFFSET = 20;

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
    /*        ENTRYPOINT V0.6 ERC-4337 PAYMASTER OVERRIDES        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @inheritdoc IPaymasterV6
    function validatePaymasterUserOp(
        UserOperation calldata userOp,
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

    /// @inheritdoc IPaymasterV6
    function postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost) external override {
        _requireFromEntryPoint();
        _postOp(mode, context, actualGasCost);
    }

    /**
     * @notice Internal helper to parse and validate the userOperation's paymasterAndData.
     * @param _userOp The userOperation.
     * @param _userOpHash The userOperation hash.
     * @return (context, validationData) The context and validation data to return to the EntryPoint.
     *
     * @dev paymasterAndData for mode 0:
     * - paymaster address (20 bytes)
     * - mode and allowAllBundlers (1 byte) - lowest bit represents allowAllBundlers, rest of the bits represent mode
     * - validUntil (6 bytes)
     * - validAfter (6 bytes)
     * - signature (64 or 65 bytes)
     *
     * @dev paymasterAndData for mode 1:
     * - paymaster address (20 bytes)
     * - mode and allowAllBundlers (1 byte) - lowest bit represents allowAllBundlers, rest of the bits represent mode
     * - constantFeePresent and recipientPresent and preFundPresent (1 byte) - 0000{preFundPresent bit}{recipientPresent
     * bit}{constantFeePresent bit}
     * - validUntil (6 bytes)
     * - validAfter (6 bytes)
     * - token address (20 bytes)
     * - postOpGas (16 bytes)
     * - exchangeRate (32 bytes)
     * - paymasterValidationGasLimit (16 bytes)
     * - treasury (20 bytes)
     * - preFund (16 bytes - only if preFundPresent is 1)
     * - constantFee (16 bytes - only if constantFeePresent is 1)
     * - recipient (20 bytes - only if recipientPresent is 1)
     * - signature (64 or 65 bytes)
     *
     */
    function _validatePaymasterUserOp(
        UserOperation calldata _userOp,
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
            (context, validationData) = _validateERC20Mode(_userOp, paymasterConfig, _userOpHash, _requiredPreFund);
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
        UserOperation calldata _userOp,
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

        emit UserOperationSponsored(_userOpHash, _userOp.sender, VERIFYING_MODE, address(0), 0, 0);
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
        UserOperation calldata _userOp,
        bytes calldata _paymasterConfig,
        bytes32 _userOpHash,
        uint256 _requiredPreFund
    )
        internal
        returns (bytes memory, uint256)
    {
        ERC20PaymasterData memory cfg = _parseErc20Config(_paymasterConfig);

        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(getHash(ERC20_MODE, _userOp));
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

    /**
     * @notice Handles ERC-20 token payment.
     * @dev PostOp is skipped in verifying mode because paymaster's postOp isn't called when context is empty.
     * @param _context The encoded ERC-20 paymaster context.
     * @param _actualGasCost The total gas cost (in wei) of this userOperation.
     */
    function _postOp(PostOpMode, bytes calldata _context, uint256 _actualGasCost) internal {
        ERC20PostOpContext memory ctx = _parsePostOpContext(_context);

        uint256 actualUserOpFeePerGas = _calculateActualUserOpFeePerGas(ctx.maxFeePerGas, ctx.maxPriorityFeePerGas);

        uint256 costInToken =
            getCostInToken(_actualGasCost, ctx.postOpGas, actualUserOpFeePerGas, ctx.exchangeRate) + ctx.constantFee;

        uint256 tokenToTransfer =
            costInToken > ctx.preFundCharged ? costInToken - ctx.preFundCharged : ctx.preFundCharged - costInToken;

        // There is a bug in EntryPoint v0.6 where if postOp reverts where the revert bytes are less than 32bytes,
        // it will revert the whole bundle instead of just force failing the userOperation.
        // To avoid this we need to use `trySafeTransferFrom` to catch when it revert and throw a custom
        // revert with more than 32 bytes. More info: https://github.com/eth-infinitism/account-abstraction/pull/293
        bool success = SafeTransferLib.trySafeTransferFrom(
            ctx.token,
            costInToken > ctx.preFundCharged ? ctx.sender : ctx.treasury,
            costInToken > ctx.preFundCharged ? ctx.treasury : ctx.sender,
            tokenToTransfer
        );

        if (!success) {
            revert PostOpTransferFromFailed("TRANSFER_FROM_FAILED");
        }

        uint256 preFundInToken = ctx.preFund * ctx.exchangeRate / 1e18;
        if (ctx.recipient != address(0) && preFundInToken > costInToken) {
            _transferRecipient(ctx.token, ctx.sender, ctx.recipient, preFundInToken - costInToken);
        }

        emit UserOperationSponsored(ctx.userOpHash, ctx.sender, ERC20_MODE, ctx.token, costInToken, ctx.exchangeRate);
    }

    function _transferRecipient(address _token, address _sender, address _recipient, uint256 _costInToken) internal {
        // There is a bug in EntryPoint v0.6 where if postOp reverts where the revert bytes are less than 32bytes,
        // it will revert the whole bundle instead of just force failing the userOperation.
        // To avoid this we need to use `trySafeTransferFrom` to catch when it revert and throw a custom
        // revert with more than 32 bytes. More info: https://github.com/eth-infinitism/account-abstraction/pull/293
        bool success = SafeTransferLib.trySafeTransferFrom(_token, _sender, _recipient, _costInToken);

        if (!success) {
            revert PostOpTransferFromFailed("TRANSFER_TO_RECIPIENT_FAILED");
        }
    }

    /**
     * @notice Calculates the actual gas price for a user operation
     * @param _maxFeePerGas The maximum fee per gas the user is willing to pay
     * @param _maxPriorityFeePerGas The maximum priority fee per gas the user is willing to pay
     * @return The actual gas price to use
     */
    function _calculateActualUserOpFeePerGas(
        uint256 _maxFeePerGas,
        uint256 _maxPriorityFeePerGas
    )
        internal
        view
        returns (uint256)
    {
        if (_maxFeePerGas == _maxPriorityFeePerGas) {
            // chains that only support legacy (pre EIP-1559 transactions)
            return _maxFeePerGas;
        } else {
            return Math.min(_maxFeePerGas, _maxPriorityFeePerGas + block.basefee);
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PUBLIC HELPERS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @notice Hashses the userOperation data when used in verifying mode.
     * @param _mode The mode that we want to get the hash for.
     * @param _userOp The user operation data.
     * @return bytes32 The hash that the signer should sign over.
     */
    function getHash(uint8 _mode, UserOperation calldata _userOp) public view returns (bytes32) {
        if (_mode == VERIFYING_MODE) {
            return _getHash(_userOp, VERIFYING_PAYMASTER_DATA_LENGTH + MODE_AND_ALLOW_ALL_BUNDLERS_LENGTH);
        } else {
            uint8 paymasterDataLength = ERC20_PAYMASTER_DATA_LENGTH + MODE_AND_ALLOW_ALL_BUNDLERS_LENGTH;

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
    function _getHash(UserOperation calldata _userOp, uint256 paymasterDataLength) internal view returns (bytes32) {
        bytes32 userOpHash = keccak256(
            abi.encode(
                _userOp.sender,
                _userOp.nonce,
                _userOp.callGasLimit,
                _userOp.verificationGasLimit,
                _userOp.preVerificationGas,
                _userOp.maxFeePerGas,
                _userOp.maxPriorityFeePerGas,
                keccak256(_userOp.callData),
                keccak256(_userOp.initCode),
                // hashing over all paymaster fields besides signature
                keccak256(_userOp.paymasterAndData[:PAYMASTER_DATA_OFFSET + paymasterDataLength])
            )
        );

        return keccak256(abi.encode(userOpHash, block.chainid));
    }
}
