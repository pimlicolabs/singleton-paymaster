// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/* solhint-disable reason-string */

import { AccessControl } from "@openzeppelin-v5.0.2/contracts/access/AccessControl.sol";
import { IAccessControl } from "@openzeppelin-v5.0.2/contracts/access/IAccessControl.sol";
import { IERC165 } from "@openzeppelin-v5.0.2/contracts/utils/introspection/IERC165.sol";
import { IEntryPoint } from "@account-abstraction-v7/interfaces/IEntryPoint.sol";

/**
 * Helper class for creating a contract with multiple valid signers.
 */
abstract contract ManagerAccessControl is AccessControl {
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");
}

interface IManagerAccessControl {
    function MANAGER_ROLE() external view returns (bytes32);

    error AccessControlUnauthorizedAccount(address account, bytes32 neededRole);
}
