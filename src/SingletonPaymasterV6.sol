// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {BasePaymaster} from "./base/BasePaymaster.sol";
import {BaseSingletonPaymaster} from "./base/BaseSingletonPaymaster.sol";
import {BaseSingletonPaymasterV6} from "./base/BaseSingletonPaymasterV6.sol";

contract SingletonPaymasterV6 is BaseSingletonPaymaster, BasePaymaster, BaseSingletonPaymasterV6 {
    constructor(address _entryPoint, address _owner)
        BasePaymaster(_entryPoint, _owner)
        BaseSingletonPaymaster(_owner)
        BaseSingletonPaymasterV6()
    {}
}
