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
    mapping(address entryPoint => bool isValid) public entryPoints;

    constructor(address[] memory _entryPoints, address _owner)
        BaseSingletonPaymaster(_owner)
        BaseMultiPaymaster(_owner)
        BaseSingletonPaymasterV6(_entryPoints[0])
        BaseSingletonPaymasterV7(_entryPoints[1])
    {
        for (uint256 i = 0; i < _entryPoints.length; i++) {
            entryPoints[_entryPoints[i]] = true;
        }
    }

    function _requireFromEntryPoint() internal view override(BaseSingletonPaymasterV6, BaseSingletonPaymasterV7) {
        require(entryPoints[msg.sender], "Sender not EntryPoint");
    }
}
