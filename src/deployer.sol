// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import { ECDSA } from "@openzeppelin-v5.0.2/contracts/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from "@openzeppelin-v5.0.2/contracts/utils/cryptography/MessageHashUtils.sol";
import { SingletonPaymasterV6 } from "./SingletonPaymasterV6.sol";
import { SingletonPaymasterV7 } from "./SingletonPaymasterV7.sol";
import { SingletonPaymasterV8 } from "./SingletonPaymasterV8.sol";

// Base deployer with shared functionality
abstract contract BaseDeployer {
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");

    address private constant SIGNER = 0x69696943154cB76175ABdA777Cc4260c0668Dd80;

    function _verifyProof(bytes memory _proof) internal view returns (bool) {
        bytes32 messageHash = MessageHashUtils.toEthSignedMessageHash(keccak256(abi.encode(block.chainid)));
        address recoveredSigner = ECDSA.recover(messageHash, _proof);
        return recoveredSigner == SIGNER;
    }
}

contract PaymasterDeployerV6 is BaseDeployer {
    constructor() { }

    function deployPaymaster(
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
        require(_verifyProof(_proof), "Invalid proof signature");

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
        address singletonPaymaster = address(bytes20(b));
        require(singletonPaymaster != address(0), "Failed to deploy SingletonPaymasterV6");

        // Add signers
        for (uint256 i = 0; i < _signers.length; i++) {
            SingletonPaymasterV6(singletonPaymaster).addSigner(_signers[i]);
        }

        // Transfer manager role
        SingletonPaymasterV6(singletonPaymaster).grantRole(MANAGER_ROLE, _manager);
        SingletonPaymasterV6(singletonPaymaster).revokeRole(MANAGER_ROLE, address(this));

        // Transfer ownership
        SingletonPaymasterV6(singletonPaymaster).grantRole(DEFAULT_ADMIN_ROLE, _owner);
        SingletonPaymasterV6(singletonPaymaster).revokeRole(DEFAULT_ADMIN_ROLE, address(this));
    }
}

contract PaymasterDeployerV7 is BaseDeployer {
    constructor() { }

    function deployPaymaster(
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
        require(_verifyProof(_proof), "Invalid proof signature");

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
        address singletonPaymaster = address(bytes20(b));
        require(singletonPaymaster != address(0), "Failed to deploy SingletonPaymasterV7");

        // Add signers
        for (uint256 i = 0; i < _signers.length; i++) {
            SingletonPaymasterV7(singletonPaymaster).addSigner(_signers[i]);
        }

        // Transfer manager role
        SingletonPaymasterV7(singletonPaymaster).grantRole(MANAGER_ROLE, _manager);
        SingletonPaymasterV7(singletonPaymaster).revokeRole(MANAGER_ROLE, address(this));

        // Transfer ownership
        SingletonPaymasterV7(singletonPaymaster).grantRole(DEFAULT_ADMIN_ROLE, _owner);
        SingletonPaymasterV7(singletonPaymaster).revokeRole(DEFAULT_ADMIN_ROLE, address(this));
    }
}

contract PaymasterDeployerV8 is BaseDeployer {
    constructor() { }

    function deployPaymaster(
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
        require(_verifyProof(_proof), "Invalid proof signature");

        // Temp signers
        address[] memory tempSigners = new address[](0);

        // Use temporary constant constructor params
        bytes memory initCode = abi.encodePacked(
            type(SingletonPaymasterV8).creationCode, abi.encode(_entryPoint, address(this), address(this), tempSigners)
        );

        bytes memory deployBytecode = abi.encodePacked(_salt, initCode);

        // Deploy using deterministic deployer
        (bool s, bytes memory b) = _deterministicDeployer.call(deployBytecode);
        require(s, "Failed to deploy SingletonPaymasterV8");

        // Handle raw address bytes (20 bytes) without assembly
        address singletonPaymaster = address(bytes20(b));
        require(singletonPaymaster != address(0), "Failed to deploy SingletonPaymasterV8");

        // Add signers
        for (uint256 i = 0; i < _signers.length; i++) {
            SingletonPaymasterV8(singletonPaymaster).addSigner(_signers[i]);
        }

        // Transfer manager role
        SingletonPaymasterV8(singletonPaymaster).grantRole(MANAGER_ROLE, _manager);
        SingletonPaymasterV8(singletonPaymaster).revokeRole(MANAGER_ROLE, address(this));

        // Transfer ownership
        SingletonPaymasterV8(singletonPaymaster).grantRole(DEFAULT_ADMIN_ROLE, _owner);
        SingletonPaymasterV8(singletonPaymaster).revokeRole(DEFAULT_ADMIN_ROLE, address(this));
    }
}
