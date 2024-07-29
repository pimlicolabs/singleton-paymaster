// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

/**
 * the interface exposed by a paymaster contract, who agrees to pay the gas for user's operations.
 * a paymaster must hold a stake to cover the required entrypoint stake and also the gas for the transaction.
 */
abstract contract EntryPointValidator {
    /**
     * Validate the call is made from a valid entrypoint.
     * Should revert if not authorized.
     */
    function _requireFromEntryPoint() internal virtual;
}
