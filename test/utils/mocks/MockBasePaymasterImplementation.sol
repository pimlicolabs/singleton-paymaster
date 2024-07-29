// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import {BasePaymaster} from "../../../src/base/BasePaymaster.sol";

contract MockBasePaymaster is BasePaymaster {
    constructor(address _entryPoint, address _owner) BasePaymaster(_entryPoint, _owner) {}

    function checkIsCallerEntryPoint() public view {
        _requireFromEntryPoint();
    }
}
