// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import { SingletonPaymasterV6 } from "./SingletonPaymasterV6.sol";
import { SingletonPaymasterV7 } from "./SingletonPaymasterV7.sol";
import { ManagerAccessControl } from "./base/ManagerAccessControl.sol";

/**
 * @title PaymasterDeployer
 * @author Pimlico
 * @notice Contract to deploy both V6 and V7 singleton paymasters with proper ownership transfer
 * @custom:security-contact security@pimlico.io
 */
contract PaymasterDeployer {
    // Constants
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");

    // Deployed paymaster addresses
    address public singletonPaymasterV6;
    address public singletonPaymasterV7;

    constructor() { }

    /**
     * @notice Deploy both singleton paymasters and transfer ownership
     * @param _entryPoint The EntryPoint contract address
     * @param _owner The final owner of the paymasters
     * @param _manager The manager address for the paymasters
     * @param _signers Array of allowed signers for the paymasters
     * @return v6 Address of the deployed SingletonPaymasterV6
     * @return v7 Address of the deployed SingletonPaymasterV7
     */
    function deployPaymasters(
        address _entryPoint,
        address _owner,
        address _manager,
        address[] memory _signers
    )
        external
        returns (address v6, address v7)
    {
        require(_entryPoint != address(0), "EntryPoint cannot be zero address");
        require(_owner != address(0), "Owner cannot be zero address");
        require(_manager != address(0), "Manager cannot be zero address");
        require(_signers.length > 0, "Must provide at least one signer");

        // Deploy paymasters with this contract as the initial owner
        SingletonPaymasterV6 paymasterV6 = new SingletonPaymasterV6(
            _entryPoint,
            address(this), // Temporary owner (this contract)
            _manager,
            _signers
        );

        SingletonPaymasterV7 paymasterV7 = new SingletonPaymasterV7(
            _entryPoint,
            address(this), // Temporary owner (this contract)
            _manager,
            _signers
        );

        // Store addresses
        singletonPaymasterV6 = address(paymasterV6);
        singletonPaymasterV7 = address(paymasterV7);

        // Transfer ownership to the real owner
        // Both paymasters inherit from AccessControl, we need to:
        // 1. Grant the role to new owner
        // 2. Revoke the role from this contract
        paymasterV6.grantRole(DEFAULT_ADMIN_ROLE, _owner);
        paymasterV6.revokeRole(DEFAULT_ADMIN_ROLE, address(this));

        paymasterV7.grantRole(DEFAULT_ADMIN_ROLE, _owner);
        paymasterV7.revokeRole(DEFAULT_ADMIN_ROLE, address(this));

        return (singletonPaymasterV6, singletonPaymasterV7);
    }
}
