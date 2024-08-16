// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {PackedUserOperation} from "@account-abstraction-v7/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "@account-abstraction-v7/interfaces/IEntryPoint.sol";
import {_packValidationData} from "@account-abstraction-v7/core/Helpers.sol";
import {UserOperationLib} from "@account-abstraction-v7/core/UserOperationLib.sol";
import {UserOperationLib as UserOperationLibV07} from "@account-abstraction-v7/core/UserOperationLib.sol";

import {ECDSA} from "@openzeppelin-v5.0.2/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin-v5.0.2/contracts/utils/cryptography/MessageHashUtils.sol";
import {Math} from "@openzeppelin-v5.0.2/contracts/utils/math/Math.sol";

import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";

import {BaseSingletonPaymaster, ERC20PaymasterData, ERC20PostOpContext} from "./base/BaseSingletonPaymaster.sol";
import {IPaymasterV7} from "./interfaces/IPaymasterV7.sol";
import {PostOpMode} from "./interfaces/PostOpMode.sol";

using UserOperationLib for PackedUserOperation;

/// @title SingletonPaymasterV7
/// @author Pimlico (https://github.com/pimlicolabs/singleton-paymaster/blob/main/src/SingletonPaymasterV7.sol)
/// @author Using Solady (https://github.com/vectorized/solady)
/// @notice An ERC-4337 Paymaster contract which supports two modes, Verifying and ERC-20.
/// In ERC-20 mode, the paymaster sponsors a UserOperation in exchange for tokens.
/// In Verifying mode, the paymaster sponsors a UserOperation and deducts prepaid balance from the user's Pimlico balance.
/// @dev Inherits from BaseSingletonPaymaster.
/// @custom:security-contact security@pimlico.io
contract SingletonPaymasterV7 is BaseSingletonPaymaster, IPaymasterV7 {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  CONSTANTS AND IMMUTABLES                  */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    uint256 private immutable PAYMASTER_DATA_OFFSET = UserOperationLibV07.PAYMASTER_DATA_OFFSET;
    uint256 private immutable PAYMASTER_VALIDATION_GAS_OFFSET = UserOperationLibV07.PAYMASTER_VALIDATION_GAS_OFFSET;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        CONSTRUCTOR                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    constructor(address _entryPoint, address _owner, address[] memory _signers)
        BaseSingletonPaymaster(_entryPoint, _owner, _signers)
    {}

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*        ENTRYPOINT V0.7 ERC-4337 PAYMASTER OVERRIDES        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @inheritdoc IPaymasterV7
    function validatePaymasterUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 maxCost)
        external
        override
        returns (bytes memory context, uint256 validationData)
    {
        _requireFromEntryPoint();
        return _validatePaymasterUserOp(userOp, userOpHash, maxCost);
    }

    /// @inheritdoc IPaymasterV7
    function postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost, uint256 actualUserOpFeePerGas)
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
     */
    function _validatePaymasterUserOp(PackedUserOperation calldata _userOp, bytes32 _userOpHash, uint256 /* maxCost */ )
        internal
        returns (bytes memory, uint256)
    {
        (uint8 mode, bytes calldata paymasterConfig) =
            _parsePaymasterAndData(_userOp.paymasterAndData, PAYMASTER_DATA_OFFSET);

        if (mode != ERC20_MODE && mode != VERIFYING_MODE) {
            revert PaymasterModeInvalid();
        }

        bytes memory context;
        uint256 validationData;

        if (mode == VERIFYING_MODE) {
            (context, validationData) = _validateVerifyingMode(_userOp, paymasterConfig, _userOpHash);
        }

        if (mode == ERC20_MODE) {
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
        PackedUserOperation calldata _userOp,
        bytes calldata _paymasterConfig,
        bytes32 _userOpHash
    ) internal returns (bytes memory, uint256) {
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
        PackedUserOperation calldata _userOp,
        bytes calldata _paymasterConfig,
        bytes32 _userOpHash
    ) internal view returns (bytes memory, uint256) {
        ERC20PaymasterData memory cfg = _parseErc20Config(_paymasterConfig);

        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(getHash(ERC20_MODE, _userOp));
        address recoveredSigner = ECDSA.recover(hash, cfg.signature);

        bool isSignatureValid = signers[recoveredSigner];
        uint256 validationData = _packValidationData(!isSignatureValid, cfg.validUntil, cfg.validAfter);

        bytes memory context = _createPostOpContext(_userOp, cfg.token, cfg.exchangeRate, cfg.postOpGas, _userOpHash);
        return (context, validationData);
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
    ) internal {
        (address sender, address token, uint256 exchangeRate, uint128 postOpGas, bytes32 userOpHash,,) =
            _parsePostOpContext(_context);

        uint256 costInToken = getCostInToken(_actualGasCost, postOpGas, _actualUserOpFeePerGas, exchangeRate);

        SafeTransferLib.safeTransferFrom(token, sender, treasury, costInToken);
        emit UserOperationSponsored(userOpHash, sender, ERC20_MODE, token, costInToken, exchangeRate);
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
    function getHash(uint8 _mode, PackedUserOperation calldata _userOp) public view returns (bytes32) {
        if (_mode == VERIFYING_MODE) {
            return _getHash(_userOp, VERIFYING_PAYMASTER_DATA_LENGTH);
        } else {
            return _getHash(_userOp, ERC20_PAYMASTER_DATA_LENGTH);
        }
    }

    /**
     * @notice Internal helper that hashes the user operation data.
     * @dev We hash over all fields in paymasterAndData but the paymaster signature.
     * @param paymasterDataLength The paymasterData length.
     * @return bytes32 The hash that the signer should sign over.
     */
    function _getHash(PackedUserOperation calldata _userOp, uint256 paymasterDataLength)
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

        return keccak256(abi.encode(userOpHash, block.chainid, address(this)));
    }
}
