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

    address public singletonPaymasterV6;
    address public singletonPaymasterV7;

    constructor() {}

    function deployPaymasters(
        bytes memory _proof,
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
        bytes32 messageHash = MessageHashUtils.toEthSignedMessageHash(keccak256(abi.encode(block.chainid)));
        address recoveredSigner = ECDSA.recover(messageHash, _proof);
        require(recoveredSigner == SIGNER, "Invalid proof signature");

        bytes memory initCodeV6 = abi.encodePacked(
            type(SingletonPaymasterV6).creationCode, abi.encode(_entryPoint, address(this), _manager, _signers)
        );

        bytes memory initCodeV7 = abi.encodePacked(
            type(SingletonPaymasterV7).creationCode, abi.encode(_entryPoint, address(this), _manager, _signers)
        );

        bytes memory deployBytecodeV6 = abi.encodePacked(_saltV6, initCodeV6);
        bytes memory deployBytecodeV7 = abi.encodePacked(_saltV7, initCodeV7);

        (bool successV6, bytes memory returnDataV6) = _deterministicDeployer.call(deployBytecodeV6);
        singletonPaymasterV6 = abi.decode(returnDataV6, (address));

        (bool successV7, bytes memory returnDataV7) = _deterministicDeployer.call(deployBytecodeV7);
        singletonPaymasterV7 = abi.decode(returnDataV7, (address));
        
        SingletonPaymasterV6(singletonPaymasterV6).grantRole(DEFAULT_ADMIN_ROLE, _owner);
        SingletonPaymasterV6(singletonPaymasterV6).revokeRole(DEFAULT_ADMIN_ROLE, address(this));

        SingletonPaymasterV7(singletonPaymasterV7).grantRole(DEFAULT_ADMIN_ROLE, _owner);
        SingletonPaymasterV7(singletonPaymasterV7).revokeRole(DEFAULT_ADMIN_ROLE, address(this));
    }
}
