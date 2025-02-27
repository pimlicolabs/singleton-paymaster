// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/* solhint-disable reason-string */

import { AccessControl } from "@openzeppelin-v5.0.2/contracts/access/AccessControl.sol";

interface IManagerAccessControl {
    function MANAGER_ROLE() external view returns (bytes32);

    error AccessControlUnauthorizedAccount(address account, bytes32 neededRole);
}

/**
 * Helper class for creating a contract with multiple valid signers.
 */
abstract contract ManagerAccessControl is AccessControl {
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");

    modifier onlyAdminOrManager() {
        if (!hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && !hasRole(ManagerAccessControl.MANAGER_ROLE, msg.sender)) {
            revert IManagerAccessControl.AccessControlUnauthorizedAccount(msg.sender, ManagerAccessControl.MANAGER_ROLE);
        }
        _;
    }
}
