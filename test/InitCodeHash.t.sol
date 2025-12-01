// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import { SingletonPaymasterV6 } from "../src/SingletonPaymasterV6.sol";
import { SingletonPaymasterV7 } from "../src/SingletonPaymasterV7.sol";
import { SingletonPaymasterV8 } from "../src/SingletonPaymasterV8.sol";
import { PaymasterDeployerV6, PaymasterDeployerV7, PaymasterDeployerV8 } from "../src/deployer.sol";

/// @notice Test contract to calculate and verify the deterministic addresses for the paymasters
contract InitCodeHashTest is Test {
    // Constants - Set these to your desired values
    address private constant DETERMINISTIC_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    address private constant ENTRY_POINT_V6 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    address private constant ENTRY_POINT_V7 = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    address private constant ENTRY_POINT_V8 = 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108;
    address private constant SIGNER = 0x69696943154cB76175ABdA777Cc4260c0668Dd80;

    bytes32 private constant SALT_V6 = bytes32(uint256(1));
    bytes32 private constant SALT_V7 = bytes32(uint256(2));

    function setUp() public { }

    function testPrintCodeV6() public pure {
        // Empty signers array for initial deployment
        address[] memory emptySigners = new address[](0);

        // Calculate and display PaymasterDeployerV6 address
        bytes32 salt = keccak256("PaymasterDeployerFactory");
        bytes memory initCode = abi.encodePacked(type(PaymasterDeployerV6).creationCode);
        address paymasterDeployerV6Address = _getCreate2Address(DETERMINISTIC_DEPLOYER, salt, initCode);
        console.log("PaymasterDeployerV6 deterministic address:", paymasterDeployerV6Address);

        // Calculate the deterministic address for V6
        console.log("V6 InitCode");
        console.logBytes(
            abi.encodePacked(
                type(SingletonPaymasterV6).creationCode,
                abi.encode(ENTRY_POINT_V6, paymasterDeployerV6Address, paymasterDeployerV6Address, emptySigners)
            )
        );
    }

    function testPrintCodeV7() public pure {
        // Empty signers array for initial deployment
        address[] memory emptySigners = new address[](0);

        // Calculate and display PaymasterDeployerV7 address
        bytes32 salt = keccak256("PaymasterDeployerFactory");
        bytes memory initCode = abi.encodePacked(type(PaymasterDeployerV7).creationCode);
        address paymasterDeployerV7Address = _getCreate2Address(DETERMINISTIC_DEPLOYER, salt, initCode);
        console.log("PaymasterDeployerV7 deterministic address:", paymasterDeployerV7Address);

        console.log("V7 InitCode");
        console.logBytes(
            abi.encodePacked(
                type(SingletonPaymasterV7).creationCode,
                abi.encode(ENTRY_POINT_V7, paymasterDeployerV7Address, paymasterDeployerV7Address, emptySigners)
            )
        );
    }

    function testPrintCodeV8() public pure {
        // Empty signers array for initial deployment
        address[] memory emptySigners = new address[](0);

        // Calculate and display PaymasterDeployerV8 address
        bytes32 salt = keccak256("PaymasterDeployerFactory");
        bytes memory initCode = abi.encodePacked(type(PaymasterDeployerV8).creationCode);
        address paymasterDeployerV8Address = _getCreate2Address(DETERMINISTIC_DEPLOYER, salt, initCode);
        console.log("PaymasterDeployerV8 deterministic address:", paymasterDeployerV8Address);

        console.log("V8 InitCode");
        console.logBytes(
            abi.encodePacked(
                type(SingletonPaymasterV8).creationCode,
                abi.encode(ENTRY_POINT_V8, paymasterDeployerV8Address, paymasterDeployerV8Address, emptySigners)
            )
        );
    }

    // Helper function to calculate CREATE2 address
    function _getCreate2Address(address deployer, bytes32 salt, bytes memory bytecode) internal pure returns (address) {
        bytes32 hash = keccak256(abi.encodePacked(bytes1(0xff), deployer, salt, keccak256(bytecode)));
        return address(uint160(uint256(hash)));
    }
}
