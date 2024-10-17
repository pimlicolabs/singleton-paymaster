// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "../src/MagicSpendPlusMinusHalf.sol";


contract MagicSpendPlusMinusHalfScript is Script {
    function setUp() public {}

    function run() public returns (address) {
        address deployer = vm.rememberKey(vm.envUint("DEPLOYER"));
        address owner = vm.rememberKey(vm.envUint("OWNER"));
        address signer = vm.rememberKey(vm.envUint("SIGNER"));
        address alice = vm.rememberKey(vm.envUint("ALICE"));

        bytes32 salt = vm.envBytes32("SALT");

        vm.startBroadcast(deployer);

        address[] memory signers = new address[](1);
        signers[0] = signer;

        MagicSpendPlusMinusHalf instance = new MagicSpendPlusMinusHalf{salt: salt}(
            owner,
            signers
        );

        vm.stopBroadcast();

        // vm.deal(alice, 1 ether);
        vm.startBroadcast(alice);

        instance.addStake{
            value: 0.05 ether
        }(
            address(0),
            0.05 ether,
            86400
        );
        vm.stopBroadcast();

        return address(instance);
    }
}
