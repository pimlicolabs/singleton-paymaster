// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { BasePaymasterTestV8 } from "./BasePaymasterTestV8.t.sol";
import { PackedUserOperation } from "account-abstraction-v7/interfaces/PackedUserOperation.sol";
import {
    PackedUserOperation as PackedUserOperationV8
} from "account-abstraction-v8/interfaces/PackedUserOperation.sol";
import { Simple7702Account } from "../utils/account-abstraction/v08/accounts/SimpleAccount7702.sol";

// 7702 account implementation for SingletonPaymasterV8
contract PaymasterTestV8_7702 is BasePaymasterTestV8 {
    // Account with EIP-7702 support
    Simple7702Account public accountImplementation;
    bytes3 constant EIP7702_PREFIX = 0xef0100;
    bytes2 constant INITCODE_EIP7702_MARKER = 0x7702;

    function setUp() public override {
        super.setUp();

        // Create the basic account implementation that will serve as our delegate
        accountImplementation = new Simple7702Account();
    }

    function createAndFundAccount(address owner) internal override returns (address) {
        // Set the EIP-7702 delegate code format:
        // 0xef0100 (EIP-7702 prefix) + delegate address (account implementation)
        bytes memory delegateCode = abi.encodePacked(EIP7702_PREFIX, address(accountImplementation));
        vm.etch(owner, delegateCode);

        // Fund the account
        vm.deal(owner, 1 ether);

        return owner;
    }

    function signUserOp(PackedUserOperation memory op, uint256 key) internal view override returns (bytes memory) {
        PackedUserOperationV8 memory opV8 = convertToPackedUserOperationV8(op);
        bytes32 hash = entryPoint.getUserOpHash(opV8);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, hash);
        return abi.encodePacked(r, s, v);
    }
}
