// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {UserOperation} from "@account-abstraction-v6/interfaces/IPaymaster.sol";
import {IEntryPoint} from "@account-abstraction-v6/interfaces/IEntryPoint.sol";
import {_packValidationData} from "@account-abstraction-v6/core/Helpers.sol";

import {ECDSA} from "@openzeppelin-v5.0.0/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin-v5.0.0/contracts/utils/cryptography/MessageHashUtils.sol";
import {Math} from "@openzeppelin-v5.0.0/contracts/utils/math/Math.sol";

import {BaseSingletonPaymaster, ERC20Config} from "./base/BaseSingletonPaymaster.sol";
import {IPaymasterV6} from "./interfaces/IPaymasterV6.sol";
import {PostOpMode} from "./interfaces/PostOpMode.sol";

import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";

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
    /*        ENTRYPOINT V0.7 ERC-4337 PAYMASTER OVERRIDES        */
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
            uint256 exchangeRate,
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

        uint256 costInToken = ((_actualGasCost + (POST_OP_GAS * actualUserOpFeePerGas)) * exchangeRate) / 1e18;

        if (_mode != PostOpMode.postOpReverted) {
            try this.attemptTransfer(token, sender, treasury, costInToken) {
                emit UserOperationSponsored(userOpHash, sender, token, true, costInToken, exchangeRate);
            } catch (bytes memory revertReason) {
                revert PostOpTransferFromFailed(revertReason);
            }
        }
    }

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

        // verifying mode
        if (mode == 0) {
            (context, validationData) = _validateVerifyingMode(_userOp, paymasterConfig, _userOpHash);
        }

        // erc20 mode
        if (mode == 1) {
            (context, validationData) = _validateERC20Mode(_userOp, paymasterConfig, _userOpHash);
        }

        return (context, validationData);
    }

    function _validateVerifyingMode(
        UserOperation calldata _userOp,
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

        emit UserOperationSponsored(_userOpHash, _userOp.sender, address(0), false, 0, 0);
        return ("", validationData);
    }

    function _validateERC20Mode(UserOperation calldata _userOp, bytes calldata _paymasterConfig, bytes32 _userOpHash)
        internal
        view
        returns (bytes memory, uint256)
    {
        ERC20Config memory cfg = _parseErc20Config(_paymasterConfig);

        bytes memory context = _createContext(_userOp, cfg.token, cfg.exchangeRate, _userOpHash);

        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(
            getHash(_userOp, cfg.validUntil, cfg.validAfter, cfg.token, cfg.exchangeRate, 0)
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
    /// @param _fundAmount The amount that the paymaster should send to
    function getHash(
        UserOperation calldata _userOp,
        uint256 _validUntil,
        uint256 _validAfter,
        address _token,
        uint256 _exchangeRate,
        uint256 _fundAmount
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

        return keccak256(
            abi.encode(
                userOpHash, block.chainid, address(this), _validUntil, _validAfter, _exchangeRate, _token, _fundAmount
            )
        );
    }

    // helper function so that we can try/catch the `safeTransferFrom`, allowing us to properly handle reverts
    function attemptTransfer(address token, address origin, address beneficiary, uint256 amount) external {
        require(msg.sender == address(this)); // this function should be called only by this contract
        SafeTransferLib.safeTransferFrom(token, origin, beneficiary, amount);
    }
}
