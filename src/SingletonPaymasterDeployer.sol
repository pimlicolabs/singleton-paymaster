// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import { SingletonPaymasterV6 } from "./SingletonPaymasterV6.sol";
import { SingletonPaymasterV7 } from "./SingletonPaymasterV7.sol";
import { Create2 } from "@openzeppelin-v5.0.2/contracts/utils/Create2.sol";
import { MultiSigner } from "./base/MultiSigner.sol";
import { ManagerAccessControl } from "./base/ManagerAccessControl.sol";
import { AccessControl } from "@openzeppelin-v5.0.2/contracts/access/AccessControl.sol";

/// @title SingletonPaymasterDeployer
/// @author Pimlico
/// @notice A deployer contract for SingletonPaymasterV6 and SingletonPaymasterV7 using CREATE2
/// @custom:security-contact security@pimlico.io
contract SingletonPaymasterDeployer {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           EVENTS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Emitted when a SingletonPaymasterV6 is deployed
    event SingletonPaymasterV6Deployed(
        address indexed paymaster,
        bytes32 indexed salt,
        address indexed entryPoint,
        address owner,
        address manager,
        address[] signers
    );

    /// @notice Emitted when a SingletonPaymasterV7 is deployed
    event SingletonPaymasterV7Deployed(
        address indexed paymaster,
        bytes32 indexed salt,
        address indexed entryPoint,
        address owner,
        address manager,
        address[] signers
    );

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PUBLIC FUNCTIONS                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Deploys a SingletonPaymasterV6 contract using CREATE2
    /// @param salt The salt for CREATE2 deployment
    /// @param entryPoint The EntryPoint contract address
    /// @param owner The owner of the paymaster
    /// @param manager The manager of the paymaster
    /// @param signers The array of signers for the paymaster
    /// @return paymaster The address of the deployed SingletonPaymasterV6
    function deploySingletonPaymasterV6(
        bytes32 salt,
        address entryPoint,
        address owner,
        address manager,
        address[] calldata signers
    )
        external
        returns (address paymaster)
    {
        // Create an empty array for signers
        address[] memory tempSigners = new address[](0);

        // Create initialization bytecode with constructor arguments
        bytes memory bytecode = abi.encodePacked(
            type(SingletonPaymasterV6).creationCode, abi.encode(entryPoint, address(this), address(this), tempSigners)
        );

        // Deploy the contract using CREATE2
        paymaster = Create2.deploy(0, salt, bytecode);

        // Transfer ownership to the specified owner by granting admin role
        AccessControl(paymaster).grantRole(0x00, owner);

        // Update manager by granting manager role
        AccessControl(paymaster).grantRole(keccak256("MANAGER_ROLE"), manager);

        // Update signers
        // First add all new signers
        for (uint256 i = 0; i < signers.length; i++) {
            MultiSigner(paymaster).addSigner(signers[i]);
        }

        emit SingletonPaymasterV6Deployed(paymaster, salt, entryPoint, owner, manager, signers);

        return paymaster;
    }

    /// @notice Deploys a SingletonPaymasterV7 contract using CREATE2
    /// @param salt The salt for CREATE2 deployment
    /// @param entryPoint The EntryPoint contract address
    /// @param owner The owner of the paymaster
    /// @param manager The manager of the paymaster
    /// @param signers The array of signers for the paymaster
    /// @return paymaster The address of the deployed SingletonPaymasterV7
    function deploySingletonPaymasterV7(
        bytes32 salt,
        address entryPoint,
        address owner,
        address manager,
        address[] calldata signers
    )
        external
        returns (address paymaster)
    {
        // Create an empty array for signers
        address[] memory tempSigners = new address[](0);

        // Create initialization bytecode with constructor arguments
        bytes memory bytecode = abi.encodePacked(
            type(SingletonPaymasterV7).creationCode, abi.encode(entryPoint, address(this), address(this), tempSigners)
        );

        // Deploy the contract using CREATE2
        paymaster = Create2.deploy(0, salt, bytecode);

        // Transfer ownership to the specified owner by granting admin role
        AccessControl(paymaster).grantRole(0x00, owner);

        // Update manager by granting manager role
        AccessControl(paymaster).grantRole(keccak256("MANAGER_ROLE"), manager);

        // Update signers
        // First add all new signers
        for (uint256 i = 0; i < signers.length; i++) {
            MultiSigner(paymaster).addSigner(signers[i]);
        }

        emit SingletonPaymasterV7Deployed(paymaster, salt, entryPoint, owner, manager, signers);

        return paymaster;
    }

    /// @notice Computes the address where a contract will be deployed using CREATE2
    /// @param salt The salt for CREATE2 deployment
    /// @param contractBytecode The contract bytecode to be deployed
    /// @return The address where the contract will be deployed
    function computeAddress(bytes32 salt, bytes memory contractBytecode) external view returns (address) {
        return Create2.computeAddress(salt, keccak256(contractBytecode));
    }

    /// @notice Computes the address where a SingletonPaymasterV6 will be deployed
    /// @param salt The salt for CREATE2 deployment
    /// @param entryPoint The EntryPoint contract address
    /// @param manager The manager of the paymaster (not used in address computation)
    /// @param signers The array of signers for the paymaster (not used in address computation)
    /// @return The address where the SingletonPaymasterV6 will be deployed
    function computeSingletonPaymasterV6Address(
        bytes32 salt,
        address entryPoint,
        address manager, // Unused parameter, included for API consistency
        address[] calldata signers // Unused parameter, included for API consistency
    )
        external
        view
        returns (address)
    {
        // Parameters manager and signers are intentionally unused as they don't affect the CREATE2 address
        // Create an empty array for signers
        address[] memory tempSigners = new address[](0);

        bytes memory bytecode = abi.encodePacked(
            type(SingletonPaymasterV6).creationCode, abi.encode(entryPoint, address(this), address(this), tempSigners)
        );
        return Create2.computeAddress(salt, keccak256(bytecode));
    }

    /// @notice Computes the address where a SingletonPaymasterV7 will be deployed
    /// @param salt The salt for CREATE2 deployment
    /// @param entryPoint The EntryPoint contract address
    /// @param manager The manager of the paymaster (not used in address computation)
    /// @param signers The array of signers for the paymaster (not used in address computation)
    /// @return The address where the SingletonPaymasterV7 will be deployed
    function computeSingletonPaymasterV7Address(
        bytes32 salt,
        address entryPoint,
        address manager, // Unused parameter, included for API consistency
        address[] calldata signers // Unused parameter, included for API consistency
    )
        external
        view
        returns (address)
    {
        // Parameters manager and signers are intentionally unused as they don't affect the CREATE2 address
        // Create an empty array for signers
        address[] memory tempSigners = new address[](0);

        bytes memory bytecode = abi.encodePacked(
            type(SingletonPaymasterV7).creationCode, abi.encode(entryPoint, address(this), address(this), tempSigners)
        );
        return Create2.computeAddress(salt, keccak256(bytecode));
    }
}
