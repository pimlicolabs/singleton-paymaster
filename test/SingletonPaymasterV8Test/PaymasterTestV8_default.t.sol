// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { BasePaymasterTestV8 } from "./BasePaymasterTestV8.t.sol";
import {
    SimpleAccountFactory,
    SimpleAccount
} from "../utils/account-abstraction/v08/accounts/SimpleAccountFactory.sol";
import { PackedUserOperation } from "account-abstraction-v7/interfaces/PackedUserOperation.sol";
import {
    PackedUserOperation as PackedUserOperationV8
} from "account-abstraction-v8/interfaces/PackedUserOperation.sol";

// Default account implementation for SingletonPaymasterV8
contract PaymasterTestV8_default is BasePaymasterTestV8 {
    SimpleAccountFactory accountFactory;
    SimpleAccount account;

    function setUp() public override {
        super.setUp();

        accountFactory = new SimpleAccountFactory(entryPoint);

        vm.prank(address(entryPoint.senderCreator()));
        account = accountFactory.createAccount(user, 0);
        vm.deal(address(account), 1 ether);
    }

    function createAndFundAccount(address owner) internal override returns (address) {
        // For tests where we need a fresh account
        vm.prank(address(entryPoint.senderCreator()));
        SimpleAccount newAccount =
            accountFactory.createAccount(owner, uint256(keccak256(abi.encode(owner, block.timestamp))));
        vm.deal(address(newAccount), 1 ether);
        return address(newAccount);
    }

    function signUserOp(PackedUserOperation memory op, uint256 key) internal view override returns (bytes memory) {
        PackedUserOperationV8 memory opV8 = convertToPackedUserOperationV8(op);
        bytes32 hash = entryPoint.getUserOpHash(opV8);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, hash);
        return abi.encodePacked(r, s, v);
    }
}
