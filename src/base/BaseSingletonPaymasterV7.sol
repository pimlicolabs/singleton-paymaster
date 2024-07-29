// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {BasePaymaster} from "./BasePaymaster.sol";
import {BaseSingletonPaymaster, ERC20Config} from "./BaseSingletonPaymaster.sol";
import {PostOpMode} from "../interfaces/PostOpMode.sol";
import {IPaymasterV7} from "../interfaces/IPaymasterV7.sol";
import {EntryPointValidator} from "../interfaces/EntryPointValidator.sol";

import {UserOperationLib} from "@account-abstraction-v7/core/UserOperationLib.sol";
import {PackedUserOperation} from "@account-abstraction-v7/interfaces/PackedUserOperation.sol";
import {_packValidationData} from "@account-abstraction-v7/core/Helpers.sol";

import {ECDSA} from "@openzeppelin-v5.0.0/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin-v5.0.0/contracts/utils/cryptography/MessageHashUtils.sol";
import {Math} from "@openzeppelin-v5.0.0/contracts/utils/math/Math.sol";

import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";

using UserOperationLib for PackedUserOperation;

abstract contract BaseSingletonPaymasterV7 is BaseSingletonPaymaster, EntryPointValidator, IPaymasterV7 {
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

    // @notice Skipped in verifying mode because postOp isn't called when context is empty.
    function _postOp(
        PostOpMode, /*_mode*/
        bytes calldata _context,
        uint256 _actualGasCost,
        uint256 _actualUserOpFeePerGas
    ) internal {
        (address sender, address token, uint256 exchangeRate, bytes32 userOpHash,,) = _parseContext(_context);
        uint256 costInToken = ((_actualGasCost + (POST_OP_GAS * _actualUserOpFeePerGas)) * exchangeRate) / 1e18;

        SafeTransferLib.safeTransferFrom(token, sender, treasury, costInToken);
        emit UserOperationSponsored(userOpHash, sender, true, costInToken, exchangeRate);
    }

    function _validatePaymasterUserOp(PackedUserOperation calldata _userOp, bytes32 _userOpHash, uint256 /* maxCost */ )
        internal
        returns (bytes memory, uint256)
    {
        (uint8 mode, uint256 fundAmount, bytes calldata paymasterConfig) =
            _parsePaymasterAndData(_userOp.paymasterAndData);

        if (mode == 0) {
            return _validateVerifyingMode(_userOp, paymasterConfig, _userOpHash, fundAmount);
        } else if (mode == 1) {
            return _validateERC20Mode(_userOp, paymasterConfig, _userOpHash, fundAmount);
        }

        // only valid modes are 1 and 0
        revert PaymasterModeInvalid();
    }

    function _validateVerifyingMode(
        PackedUserOperation calldata _userOp,
        bytes calldata _paymasterConfig,
        bytes32 _userOpHash,
        uint256 _fundAmount
    ) internal returns (bytes memory, uint256) {
        (uint48 validUntil, uint48 validAfter, bytes calldata signature) = _parseVerifyingConfig(_paymasterConfig);

        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(
            getHash(_userOp, validUntil, validAfter, address(0), 0, _fundAmount)
        );
        address verifyingSigner = ECDSA.recover(hash, signature);

        bool isSignatureValid = signers[verifyingSigner];
        uint256 validationData = _packValidationData(!isSignatureValid, validUntil, validAfter);

        emit UserOperationSponsored(_userOpHash, _userOp.getSender(), false, 0, 0);
        return ("", validationData);
    }

    function _validateERC20Mode(
        PackedUserOperation calldata _userOp,
        bytes calldata _paymasterConfig,
        bytes32 _userOpHash,
        uint256 _fundAmount
    ) internal view returns (bytes memory, uint256) {
        ERC20Config memory cfg = _parseErc20Config(_paymasterConfig);

        bytes memory context = _createContext(_userOp, cfg.token, cfg.exchangeRate, _userOpHash);

        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(
            getHash(_userOp, cfg.validUntil, cfg.validAfter, cfg.token, cfg.exchangeRate, _fundAmount)
        );
        address verifyingSigner = ECDSA.recover(hash, cfg.signature);

        bool isSignatureValid = signers[verifyingSigner];
        uint256 validationData = _packValidationData(!isSignatureValid, cfg.validUntil, cfg.validAfter);

        return (context, validationData);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PUBLIC HELPERS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Hashes the user operation data.
    /// @dev In verifying mode, _token and _exchangeRate are 0.
    /// @param _userOp The user operation data.
    /// @param _validUntil The timestamp until which the user operation is valid.
    /// @param _validAfter The timestamp after which the user operation is valid.
    /// @param _exchangeRate The maximum amount of tokens allowed for the user operation. 0 if no limit.
    function getHash(
        PackedUserOperation calldata _userOp,
        uint48 _validUntil,
        uint48 _validAfter,
        address _token,
        uint256 _exchangeRate,
        uint256 _fundAmount
    ) public view returns (bytes32) {
        address sender = _userOp.getSender();
        bytes32 userOpHash = keccak256(
            abi.encode(
                sender,
                _userOp.nonce,
                keccak256(_userOp.initCode),
                keccak256(_userOp.callData),
                _userOp.accountGasLimits,
                _userOp.preVerificationGas,
                _userOp.gasFees
            )
        );

        return keccak256(
            abi.encode(
                userOpHash, block.chainid, address(this), _validUntil, _validAfter, _exchangeRate, _token, _fundAmount
            )
        );
    }
}
