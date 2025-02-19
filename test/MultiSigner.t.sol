// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { Test, console } from "forge-std/Test.sol";

import { MultiSigner } from "../src/base/MultiSigner.sol";
import { SingletonPaymasterV7 } from "../src/SingletonPaymasterV7.sol";

contract MultiSignerTest is Test {
    MultiSigner paymaster;
    address paymasterOwner;
    address manager;

    address[] initialSigners;

    function setUp() external {
        paymasterOwner = makeAddr("paymasterOwner");
        manager = makeAddr("manager");
        paymaster = new SingletonPaymasterV7(address(0), paymasterOwner, manager, new address[](0));
    }

    function testAddSignersDuringInitialization() external {
        initialSigners.push(address(1));
        initialSigners.push(address(2));
        initialSigners.push(address(3));
        paymaster = new SingletonPaymasterV7(makeAddr("EntryPoint"), paymasterOwner, manager, initialSigners);

        vm.assertTrue(paymaster.signers(address(1)));
        vm.assertTrue(paymaster.signers(address(2)));
        vm.assertTrue(paymaster.signers(address(3)));
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
