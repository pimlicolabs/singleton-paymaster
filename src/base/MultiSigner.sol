// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/* solhint-disable reason-string */

import { ManagerAccessControl } from "./ManagerAccessControl.sol";
import { IManagerAccessControl } from "./ManagerAccessControl.sol";
import { IERC165 } from "@openzeppelin-v5.0.2/contracts/utils/introspection/IERC165.sol";
import { IEntryPoint } from "@account-abstraction-v7/interfaces/IEntryPoint.sol";

/**
 * Helper class for creating a contract with multiple valid signers.
 */
abstract contract MultiSigner is ManagerAccessControl {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           EVENTS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Emitted when a signer is added.
    event SignerAdded(address signer);

    /// @notice Emitted when a signer is removed.
    event SignerRemoved(address signer);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          STORAGE                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Mapping of valid signers.
    mapping(address account => bool isValidSigner) public signers;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CONSTRUCTOR                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    constructor(address[] memory _initialSigners) {
        for (uint256 i = 0; i < _initialSigners.length; i++) {
            signers[_initialSigners[i]] = true;
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      ADMIN FUNCTIONS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function removeSigner(address _signer) public {
        if (!hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && !hasRole(MANAGER_ROLE, msg.sender)) {
            revert IManagerAccessControl.AccessControlUnauthorizedAccount(msg.sender, MANAGER_ROLE);
        }
        signers[_signer] = false;
        emit SignerRemoved(_signer);
    }

    function addSigner(address _signer) public {
        if (!hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && !hasRole(MANAGER_ROLE, msg.sender)) {
            revert IManagerAccessControl.AccessControlUnauthorizedAccount(msg.sender, MANAGER_ROLE);
        }
        signers[_signer] = true;
        emit SignerAdded(_signer);
    }
}
