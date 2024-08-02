// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PackedUserOperation} from "@account-abstraction-v7/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "@account-abstraction-v7/interfaces/IEntryPoint.sol";
import {_packValidationData} from "@account-abstraction-v7/core/Helpers.sol";
import {UserOperationLib} from "@account-abstraction-v7/core/UserOperationLib.sol";
import {UserOperationLib as UserOperationLibV07} from "@account-abstraction-v7/core/UserOperationLib.sol";

import {ECDSA} from "@openzeppelin-v5.0.0/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin-v5.0.0/contracts/utils/cryptography/MessageHashUtils.sol";
import {Math} from "@openzeppelin-v5.0.0/contracts/utils/math/Math.sol";

import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";

import {BaseSingletonPaymaster, ERC20PaymasterData} from "./base/BaseSingletonPaymaster.sol";
import {IPaymasterV7} from "./interfaces/IPaymasterV7.sol";
import {PostOpMode} from "./interfaces/PostOpMode.sol";

using UserOperationLib for PackedUserOperation;

contract SingletonPaymasterV7 is BaseSingletonPaymaster, IPaymasterV7 {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  CONSTANTS AND IMMUTABLES                  */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
    uint256 private immutable PAYMASTER_DATA_OFFSET = UserOperationLibV07.PAYMASTER_DATA_OFFSET;
    uint256 private immutable PAYMASTER_VALIDATION_GAS_OFFSET = UserOperationLibV07.PAYMASTER_VALIDATION_GAS_OFFSET;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        CONSTRUCTOR                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    constructor(address _entryPoint, address _owner) BaseSingletonPaymaster(_entryPoint, _owner) {}

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
        (address sender, address token, uint256 exchangeRate, bytes32 userOpHash,,) = _parsePostOpContext(_context);

        // TODO: find exchange rate that works with all tokens (check chainlink implementation)
        // TODO: extract this into a public helper func
        uint256 costInToken = ((_actualGasCost + (POST_OP_GAS * _actualUserOpFeePerGas)) * exchangeRate) / 1e18;

        SafeTransferLib.safeTransferFrom(token, sender, treasury, costInToken);
        emit UserOperationSponsored(userOpHash, sender, token, true, costInToken, exchangeRate);
    }

    function _validatePaymasterUserOp(PackedUserOperation calldata _userOp, bytes32 _userOpHash, uint256 /* maxCost */ )
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

        if (mode == 0) {
            (context, validationData) = _validateVerifyingMode(_userOp, paymasterConfig, _userOpHash);
        }

        if (mode == 1) {
            (context, validationData) = _validateERC20Mode(_userOp, paymasterConfig, _userOpHash);
        }

        return (context, validationData);
    }

    function _validateVerifyingMode(
        PackedUserOperation calldata _userOp,
        bytes calldata _paymasterConfig,
        bytes32 _userOpHash
    ) internal returns (bytes memory, uint256) {
        (uint48 validUntil, uint48 validAfter, uint256 fundAmount, bytes calldata signature) =
            _parseVerifyingConfig(_paymasterConfig);

        bytes32 hash =
            MessageHashUtils.toEthSignedMessageHash(getHash(_userOp, validUntil, validAfter, address(0), 0, fundAmount));
        address verifyingSigner = ECDSA.recover(hash, signature);

        bool isSignatureValid = signers[verifyingSigner];
        uint256 validationData = _packValidationData(!isSignatureValid, validUntil, validAfter);

        // if user wants to fund their smart account with credits from the Pimlico dashboard.
        if (fundAmount > 0) {
            _distributePaymasterDeposit(payable(_userOp.sender), fundAmount);
        }

        emit UserOperationSponsored(_userOpHash, _userOp.getSender(), address(0), false, 0, 0);
        return ("", validationData);
    }

    function _validateERC20Mode(
        PackedUserOperation calldata _userOp,
        bytes calldata _paymasterConfig,
        bytes32 _userOpHash
    ) internal view returns (bytes memory, uint256) {
        ERC20PaymasterData memory cfg = _parseErc20Config(_paymasterConfig);

        bytes memory context = _createContext(_userOp, cfg.token, cfg.exchangeRate, _userOpHash);

        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(
            getHash(_userOp, cfg.validUntil, cfg.validAfter, cfg.token, cfg.exchangeRate, 0) // TODO: postop
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
    /// @dev In verifying mode, _token and _exchangeRate are always 0.
    /// @dev In paymaster mode, _fundAmount is always 0.
    /// @param _userOp The user operation data.
    /// @param _validUntil The timestamp until which the user operation is valid.
    /// @param _validAfter The timestamp after which the user operation is valid.
    /// @param _exchangeRate The maximum amount of tokens allowed for the user operation. 0 if no limit.
    /// @return bytes32 The hash that the signer should sign over.
    function getHash(
        PackedUserOperation calldata _userOp,
        uint48 _validUntil,
        uint48 _validAfter,
        address _token,
        uint256 _exchangeRate,
        uint256 _fundAmount
    )
        // TODO: postop gas
        public
        view
        returns (bytes32)
    {
        address sender = _userOp.getSender();
        bytes32 userOpHash = keccak256(
            abi.encode(
                sender,
                _userOp.nonce,
                keccak256(_userOp.initCode),
                keccak256(_userOp.callData),
                _userOp.accountGasLimits,
                uint256(bytes32(_userOp.paymasterAndData[PAYMASTER_VALIDATION_GAS_OFFSET:PAYMASTER_DATA_OFFSET])),
                // TODO: should this be from zero or 20 (this about this a bit) ??? and should we make it PAYMASTER_DATA_OFFSET + 1????
                _userOp.preVerificationGas,
                _userOp.gasFees
            )
        );

        return keccak256(
            abi.encode(
                userOpHash,
                block.chainid,
                address(this),
                _validUntil,
                _validAfter,
                _exchangeRate,
                _token,
                _fundAmount // TODO: postop
            )
        );
    }
}
