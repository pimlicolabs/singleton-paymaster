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

    function deployPaymasters(
        address _deterministicDeployer,
        bytes32 _saltV6,
        bytes32 _saltV7,
        address _entryPoint,
        address _owner,
        address _manager,
        address[] memory _signers
    )
        external
    {
        require(_deterministicDeployer != address(0), "Deterministic deployer cannot be zero address");
        require(_entryPoint != address(0), "EntryPoint cannot be zero address");
        require(_owner != address(0), "Owner cannot be zero address");
        require(_manager != address(0), "Manager cannot be zero address");
        require(_signers.length > 0, "Must provide at least one signer");

        // Generate the init bytecode for SingletonPaymasterV6 (contract bytecode + constructor args)
        bytes memory initCodeV6 = abi.encodePacked(
            type(SingletonPaymasterV6).creationCode, abi.encode(_entryPoint, address(this), _manager, _signers)
        );

        // Generate the init bytecode for SingletonPaymasterV7 (contract bytecode + constructor args)
        bytes memory initCodeV7 = abi.encodePacked(
            type(SingletonPaymasterV7).creationCode, abi.encode(_entryPoint, address(this), _manager, _signers)
        );

        // Create the full deployment bytecode with salt and init code
        bytes memory deployBytecodeV6 = abi.encodePacked(_saltV6, initCodeV6);
        bytes memory deployBytecodeV7 = abi.encodePacked(_saltV7, initCodeV7);

        // Deploy using the deterministic deployer with raw calls
        // The deterministic deployer deploys contracts via CREATE2 when receiving raw calls
        (bool successV6, bytes memory returnDataV6) = _deterministicDeployer.call(deployBytecodeV6);
        require(successV6, "V6 paymaster deployment failed");
        singletonPaymasterV6 = abi.decode(returnDataV6, (address));

        (bool successV7, bytes memory returnDataV7) = _deterministicDeployer.call(deployBytecodeV7);
        require(successV7, "V7 paymaster deployment failed");
        singletonPaymasterV7 = abi.decode(returnDataV7, (address));

        // Transfer ownership to the real owner
        // Both paymasters inherit from AccessControl, we need to:
        // 1. Grant the role to new owner
        // 2. Revoke the role from this contract
        SingletonPaymasterV6(singletonPaymasterV6).grantRole(DEFAULT_ADMIN_ROLE, _owner);
        SingletonPaymasterV6(singletonPaymasterV6).revokeRole(DEFAULT_ADMIN_ROLE, address(this));

        SingletonPaymasterV7(singletonPaymasterV7).grantRole(DEFAULT_ADMIN_ROLE, _owner);
        SingletonPaymasterV7(singletonPaymasterV7).revokeRole(DEFAULT_ADMIN_ROLE, address(this));
    }
}
