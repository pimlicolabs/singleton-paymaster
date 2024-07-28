// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {SingletonPaymasterV6} from "./implementations/SingletonPaymasterV6.sol";
import {SingletonPaymasterV7} from "./implementations/SingletonPaymasterV7.sol";
import {BaseSingletonPaymaster} from "./base/BaseSingletonPaymaster.sol";

contract SingletonPaymaster is BaseSingletonPaymaster, SingletonPaymasterV6, SingletonPaymasterV7 {
    constructor(address _entryPoint, address _owner) BaseSingletonPaymaster(_entryPoint, _owner) {}
}
