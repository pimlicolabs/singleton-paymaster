// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test, console} from "forge-std/Test.sol";

import {BaseSingletonPaymaster} from "./BaseSingletonPaymaster.sol";
import {PostOpMode} from "../interfaces/PostOpMode.sol";
import {IPaymasterV6} from "../interfaces/IPaymasterV6.sol";

import {UserOperation} from "account-abstraction-v6/interfaces/IPaymaster.sol";
import {_packValidationData} from "account-abstraction-v6/core/Helpers.sol";

import {ECDSA} from "openzeppelin-contracts-v5.0.0/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "openzeppelin-contracts-v5.0.0/contracts/utils/cryptography/MessageHashUtils.sol";
import {Math} from "openzeppelin-contracts-v5.0.0/contracts/utils/math/Math.sol";

import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";

abstract contract SingletonPaymasterV6 is BaseSingletonPaymaster, IPaymasterV6 {
    constructor() {}
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

    // @notice Skipped in verifying mode because postOp isn't called when context is empty.
    function _postOp(PostOpMode _mode, bytes calldata _context, uint256 _actualGasCost) internal {
        (
            address sender,
            address token,
            uint256 price,
            bytes32 userOpHash,
            uint256 maxFeePerGas,
            uint256 maxPriorityFeePerGas
        ) = _parseContext(_context);

        uint256 actualUserOpFeePerGas;
        if (maxFeePerGas == maxPriorityFeePerGas) {
            // chains that only support legacy (pre eip-1559 transactions)
            actualUserOpFeePerGas = maxFeePerGas;
        } else {
            actualUserOpFeePerGas = Math.min(maxFeePerGas, maxPriorityFeePerGas + block.basefee);
        }

        uint256 costInToken = ((_actualGasCost + (POST_OP_GAS * actualUserOpFeePerGas)) * price) / 1e18;

        if (_mode != PostOpMode.postOpReverted) {
            SafeTransferLib.safeTransferFrom(token, sender, treasury, costInToken);
            emit UserOperationSponsored(userOpHash, sender, true, costInToken, price);
        }
    }

    function _validatePaymasterUserOp(UserOperation calldata _userOp, bytes32 _userOpHash, uint256 /* maxCost */ )
        internal
        returns (bytes memory, uint256)
    {
        (uint8 mode, bytes calldata paymasterConfig) = _parsePaymasterAndData(_userOp.paymasterAndData);

        if (mode == 0) {
            return _validateVerifyingMode(_userOp, paymasterConfig, _userOpHash);
        } else if (mode == 1) {
            return _validateERC20Mode(_userOp, paymasterConfig, _userOpHash);
        }

        // only valid modes are 1 and 0
        revert PaymasterModeInvalid();
    }

    function _validateVerifyingMode(
        UserOperation calldata _userOp,
        bytes calldata _paymasterConfig,
        bytes32 _userOpHash
    ) internal returns (bytes memory, uint256) {
        (uint48 validUntil, uint48 validAfter, bytes calldata signature) = _parseVerifyingConfig(_paymasterConfig);
        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(getHash(_userOp, validUntil, validAfter, address(0), 0));
        address verifyingSigner = ECDSA.recover(hash, signature);

        bool isSignatureValid = signers[verifyingSigner];
        uint256 validationData = _packValidationData(!isSignatureValid, validUntil, validAfter);

        emit UserOperationSponsored(_userOpHash, _userOp.sender, false, 0, 0);
        return ("", validationData);
    }

    function _validateERC20Mode(UserOperation calldata _userOp, bytes calldata _paymasterConfig, bytes32 _userOpHash)
        internal
        view
        returns (bytes memory, uint256)
    {
        (uint48 validUntil, uint48 validAfter, address token, uint256 price, bytes calldata signature) =
            _parseErc20Config(_paymasterConfig);

        bytes memory context = _createContext(_userOp, token, price, _userOpHash);

        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(getHash(_userOp, validUntil, validAfter, token, price));
        address verifyingSigner = ECDSA.recover(hash, signature);

        bool isSignatureValid = signers[verifyingSigner];
        uint256 validationData = _packValidationData(!isSignatureValid, validUntil, validAfter);

        return (context, validationData);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PUBLIC HELPERS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Hashes the user operation data.
    /// @dev In verifying mode, _token and _price are 0.
    /// @param _userOp The user operation data.
    /// @param _validUntil The timestamp until which the user operation is valid.
    /// @param _validAfter The timestamp after which the user operation is valid.
    /// @param _price The maximum amount of tokens allowed for the user operation. 0 if no limit.
    function getHash(
        UserOperation calldata _userOp,
        uint256 _validUntil,
        uint256 _validAfter,
        address _token,
        uint256 _price
    ) public view returns (bytes32) {
        bytes32 userOpHash = keccak256(
            abi.encode(
                _userOp.sender,
                _userOp.nonce,
                keccak256(_userOp.initCode),
                keccak256(_userOp.callData),
                _userOp.callGasLimit,
                _userOp.verificationGasLimit,
                _userOp.preVerificationGas,
                _userOp.maxFeePerGas,
                _userOp.maxPriorityFeePerGas
            )
        );

        return keccak256(abi.encode(userOpHash, block.chainid, address(this), _validUntil, _validAfter, _price, _token));
    }
}
