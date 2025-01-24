// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { Test, console } from "forge-std/Test.sol";
import { MessageHashUtils } from "openzeppelin-contracts-v5.0.2/contracts/utils/cryptography/MessageHashUtils.sol";
import { Ownable } from "openzeppelin-contracts-v5.0.2/contracts/access/Ownable.sol";
import { PackedUserOperation } from "account-abstraction-v7/interfaces/PackedUserOperation.sol";
import { IEntryPoint } from "@account-abstraction-v7/interfaces/IEntryPoint.sol";

import { EntryPoint } from "./utils/account-abstraction/v07/core/EntryPoint.sol";
import { SimpleAccountFactory, SimpleAccount } from "./utils/account-abstraction/v07/samples/SimpleAccountFactory.sol";
import { SingletonPaymasterV7 } from "../src/SingletonPaymasterV7.sol";
import { BaseSingletonPaymaster } from "../src/base/BaseSingletonPaymaster.sol";
import { BasePaymaster } from "../src/base/BasePaymaster.sol";

import { TestERC20 } from "./utils/TestERC20.sol";
import { TestCounter } from "./utils/TestCounter.sol";

contract BaseSingletonPaymasterTest is Test {
    address payable beneficiary;
    address paymasterOwner;
    uint256 paymasterOwnerKey;
    address paymasterSigner;
    uint256 paymasterSignerKey;
    address user;
    uint256 userKey;

    uint256 constant INITIAL_DEPOSIT = 100 ether;
    BaseSingletonPaymaster paymaster;
    SimpleAccountFactory accountFactory;
    SimpleAccount account;
    EntryPoint entryPoint;

    TestERC20 token;
    TestCounter counter;

    function setUp() external {
        token = new TestERC20(18);
        counter = new TestCounter();

        beneficiary = payable(makeAddr("beneficiary"));
        (paymasterOwner, paymasterOwnerKey) = makeAddrAndKey("paymasterOwner");
        (paymasterSigner, paymasterSignerKey) = makeAddrAndKey("paymasterSigner");
        (user, userKey) = makeAddrAndKey("user");

        entryPoint = new EntryPoint();
        accountFactory = new SimpleAccountFactory(entryPoint);
        account = accountFactory.createAccount(user, 0);
        paymaster = new SingletonPaymasterV7(address(entryPoint), paymasterOwner, new address[](0));
        paymaster.deposit{ value: INITIAL_DEPOSIT }();

        vm.prank(paymasterOwner);
        paymaster.addSigner(paymasterSigner);
    }

    function testDeploy() external view {
        assertEq(address(paymaster.entryPoint()), address(entryPoint));
        assertEq(address(paymaster.owner()), paymasterOwner);
    }

    function testAddSigner() external {
        assertFalse(paymaster.signers(beneficiary));

        // only owner should be able to add signer.
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        paymaster.addSigner(beneficiary);

        // should pass if caller is owner.
        vm.prank(paymasterOwner);
        paymaster.addSigner(beneficiary);
        assertTrue(paymaster.signers(beneficiary));
    }

    function testRemoveSigner() external {
        // setup
        vm.prank(paymasterOwner);
        paymaster.addSigner(beneficiary);
        assertTrue(paymaster.signers(beneficiary));

        // only owner should be able to remove signer.
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        paymaster.removeSigner(beneficiary);

        // should pass if caller is owner.
        vm.prank(paymasterOwner);
        paymaster.removeSigner(beneficiary);
        assertFalse(paymaster.signers(beneficiary));
    }

    function testGetCostInToken(
        uint256 _userOperationGasUsed,
        uint256 _postOpGas,
        uint256 _actualUserOpFeePerGas,
        uint256 _exchangeRate
    )
        external
        view
    {
        uint256 postOpGas = bound(_postOpGas, 21_000, 250_000);
        uint256 actualUserOpFeePerGas = bound(_actualUserOpFeePerGas, 0.01 gwei, 5000 gwei);
        uint256 userOperationGasUsed = bound(_userOperationGasUsed, 21_000, 30_000_000);

        uint256 exchangeRate = bound(_exchangeRate, 1e6, 1e50);

        uint256 actualGasCost = userOperationGasUsed * userOperationGasUsed;
        uint256 costInToken = paymaster.getCostInToken(actualGasCost, postOpGas, actualUserOpFeePerGas, exchangeRate);
        vm.assertGt(costInToken, 0);
    }
}
