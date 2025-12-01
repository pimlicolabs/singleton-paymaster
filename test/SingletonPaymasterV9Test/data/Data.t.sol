// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {PaymasterData} from "./PaymasterData.t.sol";
import {MockERC20} from "test/SingletonPaymasterV9Test/mocks/MockERC20.sol";
import {Simple7702Account} from "test/SingletonPaymasterV9Test/mocks/Simple7702Account.sol";
import {IEntryPoint} from "lib/account-abstraction-v9/contracts/interfaces/IEntryPoint.sol";
import {SingletonPaymasterV9 as Paymaster} from "src/SingletonPaymasterV9/SingletonPaymasterV9.sol";

contract Data is PaymasterData {
    Paymaster PM;
    MockERC20 mockERC20;
    Simple7702Account account;
    Simple7702Account implementation;
    IEntryPoint public ENTRY_POINT_V9;

    uint256 forkId;

    uint256 owner7702PK;
    address owner7702;

    address sender;

    function _setData() internal {
        (owner7702, owner7702PK) = makeAddrAndKey("owner7702");
        sender = makeAddr("sender");
    }
}
