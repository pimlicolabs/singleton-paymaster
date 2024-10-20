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

        instance.deposit{value: 0.01 ether}(address(0), 0.01 ether);

        vm.stopBroadcast();

        vm.startBroadcast(alice);
        instance.addStake{value: 0.01 ether}(address(0), 0.01 ether, 2 * 86400);
        vm.stopBroadcast();

        vm.startBroadcast(owner);
        instance.addSigner(signer);
        vm.stopBroadcast();

        return address(instance);
    }
}


contract MagicSpendPlusMinusHalfAddStake is Script {
    function setUp() public {}

    function run() public {
        address alice = vm.rememberKey(vm.envUint("ALICE"));

        address payable addr = payable(0x023Cdb354f655DED93Df8F5C220Cb43F82194D92);

        MagicSpendPlusMinusHalf instance = MagicSpendPlusMinusHalf(addr);

        vm.startBroadcast(alice);
        instance.addStake{value: 0.00123 ether}(address(0), 0.00123 ether, 2 * 86400);
        vm.stopBroadcast();
    }
}