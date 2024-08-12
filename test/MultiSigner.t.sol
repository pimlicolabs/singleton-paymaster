// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Test, console} from "forge-std/Test.sol";

import {MultiSigner} from "../src/base/MultiSigner.sol";
import {SingletonPaymasterV7} from "../src/SingletonPaymasterV7.sol";

contract MultiSignerTest is Test {
    MultiSigner paymaster;
    address paymasterOwner;

    function setUp() external {
        paymasterOwner = makeAddr("paymasterOwner");
        paymaster = new SingletonPaymasterV7(address(0), paymasterOwner);
    }

    function testAddSigner() external {
        address newSigner = makeAddr("newSigner");

        vm.startPrank(paymasterOwner);
        assertFalse(paymaster.signers(newSigner));
        paymaster.addSigner(newSigner);
        assertTrue(paymaster.signers(newSigner));
        vm.stopPrank();
    }

    function testRemoveSigner() external {
        address newSigner = makeAddr("newSigner");

        vm.startPrank(paymasterOwner);
        paymaster.addSigner(newSigner);
        assertTrue(paymaster.signers(newSigner));
        paymaster.removeSigner(newSigner);
        assertFalse(paymaster.signers(newSigner));
    }
}
