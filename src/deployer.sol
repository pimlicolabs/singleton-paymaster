// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import { SingletonPaymasterV6 } from "./SingletonPaymasterV6.sol";
import { SingletonPaymasterV7 } from "./SingletonPaymasterV7.sol";
import { ManagerAccessControl } from "./base/ManagerAccessControl.sol";
import { ECDSA } from "@openzeppelin-v5.0.2/contracts/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from "@openzeppelin-v5.0.2/contracts/utils/cryptography/MessageHashUtils.sol";

contract PaymasterDeployer {
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");

    address private constant SIGNER = 0x69696943154cB76175ABdA777Cc4260c0668Dd80;

    constructor() { }

    function deployPaymasterV6(
        bytes memory _proof,
        address _deterministicDeployer,
        bytes32 _salt,
        address _entryPoint,
        address _owner,
        address _manager,
        address[] memory _signers
    )
        external
    {
        // Frontrun protection
        bytes32 messageHash = MessageHashUtils.toEthSignedMessageHash(keccak256(abi.encode(block.chainid)));
        address recoveredSigner = ECDSA.recover(messageHash, _proof);
        require(recoveredSigner == SIGNER, "Invalid proof signature");

        // Temp signers
        address[] memory tempSigners = new address[](0);

        // Use temporary constant constructor params
        bytes memory initCode = abi.encodePacked(
            type(SingletonPaymasterV6).creationCode, abi.encode(_entryPoint, address(this), address(this), tempSigners)
        );

        bytes memory deployBytecode = abi.encodePacked(_salt, initCode);

        // Deploy using deterministic deployer
        (bool s, bytes memory b) = _deterministicDeployer.call(deployBytecode);
        require(s, "Failed to deploy SingletonPaymasterV6");

        // Handle raw address bytes (20 bytes) without assembly
        address singletonPaymasterV6 = address(bytes20(b));
        require(singletonPaymasterV6 != address(0), "Failed to deploy SingletonPaymasterV6");

        // Add signers
        for (uint256 i = 0; i < _signers.length; i++) {
            SingletonPaymasterV6(singletonPaymasterV6).addSigner(_signers[i]);
        }

        // Transfer manager role
        SingletonPaymasterV6(singletonPaymasterV6).grantRole(MANAGER_ROLE, _manager);
        SingletonPaymasterV6(singletonPaymasterV6).revokeRole(MANAGER_ROLE, address(this));

        // Transfer ownership
        SingletonPaymasterV6(singletonPaymasterV6).grantRole(DEFAULT_ADMIN_ROLE, _owner);
        SingletonPaymasterV6(singletonPaymasterV6).revokeRole(DEFAULT_ADMIN_ROLE, address(this));
    }

    function deployPaymasterV7(
        bytes memory _proof,
        address _deterministicDeployer,
        bytes32 _salt,
        address _entryPoint,
        address _owner,
        address _manager,
        address[] memory _signers
    )
        external
    {
        // Frontrun protection
        bytes32 messageHash = MessageHashUtils.toEthSignedMessageHash(keccak256(abi.encode(block.chainid)));
        address recoveredSigner = ECDSA.recover(messageHash, _proof);
        require(recoveredSigner == SIGNER, "Invalid proof signature");

        // Temp signers
        address[] memory tempSigners = new address[](0);

        // Use temporary constant constructor params
        bytes memory initCode = abi.encodePacked(
            type(SingletonPaymasterV7).creationCode, abi.encode(_entryPoint, address(this), address(this), tempSigners)
        );

        bytes memory deployBytecode = abi.encodePacked(_salt, initCode);

        // Deploy using deterministic deployer
        (bool s, bytes memory b) = _deterministicDeployer.call(deployBytecode);
        require(s, "Failed to deploy SingletonPaymasterV7");

        // Handle raw address bytes (20 bytes) without assembly
        address singletonPaymasterV7 = address(bytes20(b));
        require(singletonPaymasterV7 != address(0), "Failed to deploy SingletonPaymasterV7");

        // Add signers
        for (uint256 i = 0; i < _signers.length; i++) {
            SingletonPaymasterV7(singletonPaymasterV7).addSigner(_signers[i]);
        }

        // Transfer manager role
        SingletonPaymasterV7(singletonPaymasterV7).grantRole(MANAGER_ROLE, _manager);
        SingletonPaymasterV7(singletonPaymasterV7).revokeRole(MANAGER_ROLE, address(this));

        // Transfer ownership
        SingletonPaymasterV7(singletonPaymasterV7).grantRole(DEFAULT_ADMIN_ROLE, _owner);
        SingletonPaymasterV7(singletonPaymasterV7).revokeRole(DEFAULT_ADMIN_ROLE, address(this));
    }
}

contract DeployerFactory {
    constructor(
        bytes memory _proof,
        address _deterministicDeployer,
        bytes32 _saltV6,
        bytes32 _saltV7,
        address _entryPointV6,
        address _entryPointV7,
        address _owner,
        address _manager,
        address[] memory _signers
    ) {
        // Deploy PaymasterDeployer using deterministic deployer
        bytes32 salt = keccak256("DeployerFactory");
        bytes memory initCode = abi.encodePacked(type(PaymasterDeployer).creationCode);
        bytes memory deployBytecode = abi.encodePacked(salt, initCode);

        (, bytes memory returnData) = _deterministicDeployer.call(deployBytecode);

        // Handle raw address bytes (20 bytes) without assembly
        address paymasterDeployer = address(bytes20(returnData));
        require(paymasterDeployer != address(0), "Failed to deploy PaymasterDeployer");

        PaymasterDeployer(paymasterDeployer).deployPaymasterV6(
            _proof, _deterministicDeployer, _saltV6, _entryPointV6, _owner, _manager, _signers
        );

        PaymasterDeployer(paymasterDeployer).deployPaymasterV7(
            _proof, _deterministicDeployer, _saltV7, _entryPointV7, _owner, _manager, _signers
        );
    }
}
