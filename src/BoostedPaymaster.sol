// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {UserOperation} from "@account-abstraction-v6/interfaces/IPaymaster.sol";
import {PackedUserOperation} from "@account-abstraction-v7/interfaces/PackedUserOperation.sol";
import {UserOperationLib} from "@account-abstraction-v7/core/UserOperationLib.sol";
import {BaseSingletonPaymaster} from "./base/BaseSingletonPaymaster.sol";
import {_packValidationData} from "@account-abstraction-v6/core/Helpers.sol";

using UserOperationLib for PackedUserOperation;

contract BoostedPaymaster {
    /// @notice Mode indicating that the Paymaster is in Verifying mode.
    uint8 immutable VERIFYING_MODE = 0;

    constructor() {}

    /**
     * @notice Validates a UserOperation (v6 structure) for paymaster usage.
     * @param userOp The UserOperation to validate.
     * @param userOpHash The hash of the UserOperation.
     * @return context The context to be passed to postOp.
     * @return validationData The validation data indicating success/failure.
     */
    function validatePaymasterUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256)
        external
        returns (bytes memory context, uint256 validationData)
    {
        emit BaseSingletonPaymaster.UserOperationSponsored(userOpHash, userOp.sender, VERIFYING_MODE, address(0), 0, 0);

        validationData = _packValidationData(false, 0, 0);

        return ("", validationData);
    }

    /**
     * @notice Validates a PackedUserOperation (v7 structure) for paymaster usage.
     * @param userOp The PackedUserOperation to validate.
     * @param userOpHash The hash of the UserOperation.
     * @return context The context to be passed to postOp.
     * @return validationData The validation data indicating success/failure.
     */
    function validatePaymasterUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256)
        external
        returns (bytes memory context, uint256 validationData)
    {
        emit BaseSingletonPaymaster.UserOperationSponsored(
            userOpHash, userOp.getSender(), VERIFYING_MODE, address(0), 0, 0
        );

        validationData = _packValidationData(false, 0, 0);

        return ("", validationData);
    }
}
