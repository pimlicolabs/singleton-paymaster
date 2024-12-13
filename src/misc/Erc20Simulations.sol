// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { UserOperation } from "account-abstraction-v6/interfaces/UserOperation.sol";
import { IEntryPoint as IEntryPointV6 } from "account-abstraction-v6/interfaces/IEntryPoint.sol";

import { Test, console2 } from "forge-std/Test.sol";

// Contract that returns the treasury balance change
contract Erc20PaymasterSimulationsV6 {
    error EntryPointError(bytes);

    constructor(IERC20 token, UserOperation memory userOperation, address entryPoint, address treasury) {
        uint256 balanceBefore = token.balanceOf(treasury);

        (, bytes memory b) = entryPoint.call(
            abi.encodeWithSelector(
                IEntryPointV6.simulateHandleOp.selector,
                userOperation,
                address(token),
                abi.encodeWithSignature("balanceOf(address)", treasury)
            )
        );

        // Check that we get back the expected function selector
        bytes4 returnedSelector;
        assembly {
            returnedSelector := mload(add(b, 32))
        }
        bytes4 expectedSelector = IEntryPointV6.ExecutionResult.selector;
        if (returnedSelector != expectedSelector) {
            revert EntryPointError(b);
        }

        // Slice the ExecutionResult to remove the first 4 bytes (selector)
        bytes memory actualData = new bytes(b.length - 4);
        for (uint256 i = 0; i < b.length - 4; i++) {
            actualData[i] = b[i + 4];
        }

        // Decode the remaining data
        (,,,,, bytes memory targetResult) = abi.decode(actualData, (uint256, uint256, uint48, uint48, bool, bytes));
        uint256 balanceAfter = abi.decode(targetResult, (uint256));

        // Decode balanceAfter from target call.
        uint256 balanceChange = balanceAfter - balanceBefore;

        assembly {
            mstore(0x80, balanceChange)
            return(0x80, 32)
        }
    }
}

contract PimlicoErc20PaymasterSimulationsV7 { }
