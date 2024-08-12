// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {UserOperation} from "@account-abstraction-v6/interfaces/IPaymaster.sol";
import {IEntryPoint} from "@account-abstraction-v6/interfaces/IEntryPoint.sol";
import {_packValidationData} from "@account-abstraction-v6/core/Helpers.sol";

import {ECDSA} from "@openzeppelin-v5.0.2/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin-v5.0.2/contracts/utils/cryptography/MessageHashUtils.sol";
import {Math} from "@openzeppelin-v5.0.2/contracts/utils/math/Math.sol";

import {BaseSingletonPaymaster, ERC20PaymasterData, ERC20PostOpContext} from "./base/BaseSingletonPaymaster.sol";
import {IPaymasterV6} from "./interfaces/IPaymasterV6.sol";
import {PostOpMode} from "./interfaces/PostOpMode.sol";

import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";

/// @title SingletonPaymasterV6
/// @author Pimlico (https://github.com/pimlicolabs/singleton-paymaster/blob/main/src/SingletonPaymasterV6.sol)
/// @author Using Solady (https://github.com/vectorized/solady)
/// @notice An ERC-4337 Paymaster contract which supports two modes, Verifying and ERC-20.
/// In ERC-20 mode, the paymaster sponsors a UserOperation in exchange for tokens.
/// In Verifying mode, the paymaster sponsors a UserOperation from the user's Pimlico balance.
/// In Verifying mode, the user also has the option to fund their smart account using their Pimlico balance.
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

    constructor(address _entryPoint, address _owner) BaseSingletonPaymaster(_entryPoint, _owner) {}

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*        ENTRYPOINT V0.6 ERC-4337 PAYMASTER OVERRIDES        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @inheritdoc IPaymasterV6
    function validatePaymasterUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 maxCost)
        external
        override
        returns (bytes memory context, uint256 validationData)
    {
        _requireFromEntryPoint();
        return _validatePaymasterUserOp(userOp, userOpHash, maxCost);
    }

    /// @inheritdoc IPaymasterV6
    function postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost) external override {
        _requireFromEntryPoint();
        _postOp(mode, context, actualGasCost);
    }

    /**
     * @notice Handles ERC-20 token payment.
     * @dev PostOp is skipped in verifying mode because paymaster's postOp isn't called when context is empty.
     * @param _mode The postOp mode.
     * @param _context The encoded ERC-20 paymaster context.
     * @param _actualGasCost The total gas cost (in wei) of this userOperation.
     */
    function _postOp(PostOpMode _mode, bytes calldata _context, uint256 _actualGasCost) internal {
        (
            address sender,
            address token,
            uint256 exchangeRate,
            uint128 postOpGas,
            bytes32 userOpHash,
            uint256 maxFeePerGas,
            uint256 maxPriorityFeePerGas
        ) = _parsePostOpContext(_context);

        uint256 actualUserOpFeePerGas;
        if (maxFeePerGas == maxPriorityFeePerGas) {
            // chains that only support legacy (pre EIP-1559 transactions)
            actualUserOpFeePerGas = maxFeePerGas;
        } else {
            actualUserOpFeePerGas = Math.min(maxFeePerGas, maxPriorityFeePerGas + block.basefee);
        }

        uint256 costInToken = getCostInToken(_actualGasCost, postOpGas, actualUserOpFeePerGas, exchangeRate);

        if (_mode != PostOpMode.postOpReverted) {
            // There is a bug in EntryPoint v0.6 where if postOp reverts where the revert bytes are less than 32bytes,
            // it will revert the whole bundle instead of just force failing the userOperation.
            // To avoid this we need to use `trySafeTransferFrom` to catch when it revert and throw a custom
            // revert with more than 32 bytes. More info: https://github.com/eth-infinitism/account-abstraction/pull/293
            bool success = SafeTransferLib.trySafeTransferFrom(token, sender, treasury, costInToken);

            if (!success) {
                revert PostOpTransferFromFailed("TRANSFER_FROM_FAILED");
            }

            emit UserOperationSponsored(userOpHash, sender, ERC20_MODE, token, costInToken, exchangeRate);
        }
    }

    /**
     * @notice Internal helper to parse and validate the userOperation's paymasterAndData.
     * @param _userOp The userOperation.
     * @param _userOpHash The userOperation hash.
     * @return (context, validationData) The context and validation data to return to the EntryPoint.
     */
    function _validatePaymasterUserOp(UserOperation calldata _userOp, bytes32 _userOpHash, uint256 /* maxCost */ )
        internal
        returns (bytes memory, uint256)
    {
        (uint8 mode, bytes calldata paymasterConfig) =
            _parsePaymasterAndData(_userOp.paymasterAndData, PAYMASTER_DATA_OFFSET);

        if (mode > 1) {
            revert PaymasterModeInvalid();
        }

        bytes memory context;
        uint256 validationData;

        // Verifying mode
        if (mode == 0) {
            (context, validationData) = _validateVerifyingMode(_userOp, paymasterConfig, _userOpHash);
        }

        // ERC-20 mode
        if (mode == 1) {
            (context, validationData) = _validateERC20Mode(_userOp, paymasterConfig, _userOpHash);
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
    ) internal returns (bytes memory, uint256) {
        (uint48 validUntil, uint48 validAfter, bytes calldata signature) = _parseVerifyingConfig(_paymasterConfig);

        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(getHash(_userOp, validUntil, validAfter));
        address recoveredSigner = ECDSA.recover(hash, signature);

        bool isSignatureValid = signers[recoveredSigner];
        uint256 validationData = _packValidationData(!isSignatureValid, validUntil, validAfter);

        emit UserOperationSponsored(_userOpHash, _userOp.sender, 0, address(0), 0, 0);
        return ("", validationData);
    }

    /**
     * @notice Internal helper to validate the paymasterAndData when used in ERC-20 mode.
     * @param _userOp The userOperation.
     * @param _paymasterConfig The encoded paymaster config taken from paymasterAndData.
     * @param _userOpHash The userOperation hash.
     * @return (context, validationData) The validation data to return to the EntryPoint.
     */
    function _validateERC20Mode(UserOperation calldata _userOp, bytes calldata _paymasterConfig, bytes32 _userOpHash)
        internal
        view
        returns (bytes memory, uint256)
    {
        ERC20PaymasterData memory cfg = _parseErc20Config(_paymasterConfig);

        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(
            getHash(_userOp, cfg.validUntil, cfg.validAfter, cfg.token, cfg.postOpGas, cfg.exchangeRate)
        );
        address recoveredSigner = ECDSA.recover(hash, cfg.signature);

        bool isSignatureValid = signers[recoveredSigner];
        uint256 validationData = _packValidationData(!isSignatureValid, cfg.validUntil, cfg.validAfter);

        bytes memory context = _createPostOpContext(_userOp, cfg.token, cfg.exchangeRate, cfg.postOpGas, _userOpHash);
        return (context, validationData);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PUBLIC HELPERS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @notice Hashses the userOperation data when used in ERC-20 mode.
     * @param _userOp The user operation data.
     * @param _validUntil The timestamp until which the user operation is valid.
     * @param _validAfter The timestamp after which the user operation is valid.
     * @param _token The payment token.
     * @param _exchangeRate The token exchange rate used during payment calculation.
     * @param _postOpGas The gas to cover the overhead of the postOp transferFrom call.
     * @return bytes32 The hash that the signer should sign over.
     */
    function getHash(
        UserOperation calldata _userOp,
        uint48 _validUntil,
        uint48 _validAfter,
        address _token,
        uint128 _postOpGas,
        uint256 _exchangeRate
    ) public view returns (bytes32) {
        return _getHash(_userOp, _validUntil, _validAfter, _token, _postOpGas, _exchangeRate);
    }

    /**
     * @notice Hashses the userOperation data when used in verifying mode.
     * @param _userOp The user operation data.
     * @param _validUntil The timestamp until which the user operation is valid.
     * @param _validAfter The timestamp after which the user operation is valid.
     * @return bytes32 The hash that the signer should sign over.
     */
    function getHash(UserOperation calldata _userOp, uint48 _validUntil, uint48 _validAfter)
        public
        view
        returns (bytes32)
    {
        return _getHash(_userOp, _validUntil, _validAfter, address(0), 0, 0);
    }

    /**
     * @notice Internal helper that hashes the user operation data.
     * @dev In verifying mode, _token, _exchangeRate, and _postOpGas are always 0.
     * @dev In paymaster mode, _fundAmount is always 0.
     * @param _userOp The user operation data.
     * @param _validUntil The timestamp until which the user operation is valid.
     * @param _validAfter The timestamp after which the user operation is valid.
     * @param _exchangeRate The exchange used during cost calculation.
     * @return bytes32 The hash that the signer should sign over.
     */
    function _getHash(
        UserOperation calldata _userOp,
        uint256 _validUntil,
        uint256 _validAfter,
        address _token,
        uint128 _postOpGas,
        uint256 _exchangeRate
    ) internal view returns (bytes32) {
        bytes32 userOpHash;
        {
            // inner scopes needed to avoid stack too deep error.
            bytes memory blob;
            {
                blob = abi.encode(
                    _userOp.sender,
                    _userOp.nonce,
                    keccak256(_userOp.initCode),
                    keccak256(_userOp.callData),
                    _userOp.callGasLimit,
                    _userOp.verificationGasLimit,
                    _userOp.preVerificationGas
                );
            }
            {
                blob = abi.encode(
                    blob,
                    // hashing over paymaster mode.
                    uint8(bytes1(_userOp.paymasterAndData[PAYMASTER_DATA_OFFSET:PAYMASTER_DATA_OFFSET + 1])),
                    _userOp.maxFeePerGas,
                    _userOp.maxPriorityFeePerGas
                );
            }
            userOpHash = keccak256(blob);
        }

        return keccak256(
            abi.encode(
                userOpHash, block.chainid, address(this), _validUntil, _validAfter, _exchangeRate, _token, _postOpGas
            )
        );
    }
}
