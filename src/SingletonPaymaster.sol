// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {BaseMultiPaymaster} from "./base/BaseMultiPaymaster.sol";
import {BaseSingletonPaymaster} from "./base/BaseSingletonPaymaster.sol";
import {BaseSingletonPaymasterV6} from "./base/BaseSingletonPaymasterV6.sol";
import {BaseSingletonPaymasterV7} from "./base/BaseSingletonPaymasterV7.sol";

contract SingletonPaymaster is
    BaseSingletonPaymaster,
    BaseMultiPaymaster,
    BaseSingletonPaymasterV6,
    BaseSingletonPaymasterV7
{
    constructor(address[] memory _entryPoints, address _owner)
        BaseSingletonPaymaster(_owner)
        BaseMultiPaymaster(_entryPoints, _owner)
        BaseSingletonPaymasterV6()
        BaseSingletonPaymasterV7()
    {}
}
