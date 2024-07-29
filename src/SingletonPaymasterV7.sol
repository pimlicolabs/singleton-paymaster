// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {BasePaymaster} from "./base/BasePaymaster.sol";
import {BaseSingletonPaymaster} from "./base/BaseSingletonPaymaster.sol";
import {BaseSingletonPaymasterV7} from "./base/BaseSingletonPaymasterV7.sol";

contract SingletonPaymasterV7 is BaseSingletonPaymaster, BasePaymaster, BaseSingletonPaymasterV7 {
    constructor(address _entryPoint, address _owner)
        BasePaymaster(_entryPoint, _owner)
        BaseSingletonPaymaster(_owner)
        BaseSingletonPaymasterV7()
    {}
}
