// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

/* solhint-disable reason-string */
import {BasePaymaster} from "./BasePaymaster.sol";
import {IPaymasterV6} from "../interfaces/IPaymasterV6.sol";
import {IPaymasterV7} from "../interfaces/IPaymasterV7.sol";
import {PostOpMode} from "../interfaces/PostOpMode.sol";

import {UserOperation} from "account-abstraction-v6/interfaces/IPaymaster.sol";
import {PackedUserOperation} from "account-abstraction-v7/interfaces/PackedUserOperation.sol";

abstract contract BaseSingletonPaymaster is IPaymasterV6, IPaymasterV7, BasePaymaster {
    constructor(address _entryPoint, address _owner) BasePaymaster(_entryPoint, _owner) {}

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

    // @dev postOperation handler for version v0.6
    function _postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost) internal virtual {
        (mode, context, actualGasCost);
        revert("must override");
    }

    function _postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost, uint256 actualUserOpFeePerGas)
        internal
        virtual
    {
        (mode, context, actualGasCost, actualUserOpFeePerGas);
        revert("must override");
    }

    // @dev postOperation handler for version v0.7
    function _validatePaymasterUserOp(PackedUserOperation calldata _userOp, bytes32 _userOpHash, uint256 maxCost)
        internal
        virtual
        returns (bytes memory, uint256);

    function _validatePaymasterUserOp(UserOperation calldata _userOp, bytes32 _userOpHash, uint256 maxCost)
        internal
        virtual
        returns (bytes memory, uint256);
}
