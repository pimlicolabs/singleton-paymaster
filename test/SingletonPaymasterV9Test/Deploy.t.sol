// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {MockERC20} from "test/SingletonPaymasterV9Test/mocks/MockERC20.sol";
import {EntryPoint} from "lib/account-abstraction-v9/contracts/core/EntryPoint.sol";
import {PaymasterHelper} from "test/SingletonPaymasterV9Test/helpers/PaymasterHelper.t.sol";
import {Simple7702Account} from "test/SingletonPaymasterV9Test/mocks/Simple7702Account.sol";
import {IEntryPoint} from "lib/account-abstraction-v9/contracts/interfaces/IEntryPoint.sol";
import {SingletonPaymasterV9 as Paymaster} from "src/SingletonPaymasterV9/SingletonPaymasterV9.sol";

contract Deploy is PaymasterHelper {
    function setUp() public virtual {
        forkId = vm.createFork(SEPOLIA_RPC_URL);
        vm.selectFork(forkId);

        _setPaymasterData();
        _setData();

        EntryPoint deployedEntryPoint = new EntryPoint();
        vm.etch(entryPointV9, address(deployedEntryPoint).code);
        vm.label(entryPointV9, "EntryPointV9");
        ENTRY_POINT_V9 = IEntryPoint(payable(entryPointV9));

        mockERC20 = new MockERC20();
        account = new Simple7702Account();
        implementation = account;
        PM = new Paymaster(address(ENTRY_POINT_V9), owner, manager, signers);

        _etch();
        _deal();
        _depositToEP();
    }

    function _deal() internal {
        deal(owner, 10 ether);
        deal(owner7702, 10 ether);
    }

    function _mintAndApprove(address _owner, uint256 _value) internal {
        vm.startPrank(owner7702);
        mockERC20.mint(_owner, _value);
        mockERC20.approve(address(PM), type(uint256).max);
        vm.stopPrank();
    }
}
