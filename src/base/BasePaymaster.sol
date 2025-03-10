// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/* solhint-disable reason-string */

import { ManagerAccessControl } from "./ManagerAccessControl.sol";
import { IEntryPoint } from "@account-abstraction-v7/interfaces/IEntryPoint.sol";

/**
 * Helper class for creating a paymaster.
 * provides helper methods for staking.
 * Validates that the postOp is called only by the entryPoint.
 */
abstract contract BasePaymaster is ManagerAccessControl {
    IEntryPoint public immutable entryPoint;

    constructor(address _entryPoint, address _owner, address _manager) {
        entryPoint = IEntryPoint(_entryPoint);
        _grantRole(DEFAULT_ADMIN_ROLE, _owner);
        _grantRole(MANAGER_ROLE, _manager);
    }

    /**
     * Add a deposit for this paymaster, used for paying for transaction fees.
     */
    function deposit() public payable {
        entryPoint.depositTo{ value: msg.value }(address(this));
    }

    /**
     * Withdraw value from the deposit.
     * @param withdrawAddress - Target to send to.
     * @param amount          - Amount to withdraw.
     */
    function withdrawTo(address payable withdrawAddress, uint256 amount) public onlyRole(DEFAULT_ADMIN_ROLE) {
        entryPoint.withdrawTo(withdrawAddress, amount);
    }

    /**
     * Add stake for this paymaster.
     * This method can also carry eth value to add to the current stake.
     * @param unstakeDelaySec - The unstake delay for this paymaster. Can only be increased.
     */
    function addStake(uint32 unstakeDelaySec) external payable onlyAdminOrManager {
        entryPoint.addStake{ value: msg.value }(unstakeDelaySec);
    }

    /**
     * Return current paymaster's deposit on the entryPoint.
     */
    function getDeposit() public view returns (uint256) {
        return entryPoint.balanceOf(address(this));
    }

    /**
     * Unlock the stake, in order to withdraw it.
     * The paymaster can't serve requests once unlocked, until it calls addStake again
     */
    function unlockStake() external onlyAdminOrManager {
        entryPoint.unlockStake();
    }

    /**
     * Withdraw the entire paymaster's stake.
     * stake must be unlocked first (and then wait for the unstakeDelay to be over)
     * @param withdrawAddress - The address to send withdrawn value.
     */
    function withdrawStake(address payable withdrawAddress) external onlyRole(DEFAULT_ADMIN_ROLE) {
        entryPoint.withdrawStake(withdrawAddress);
    }

    /**
     * Validate the call is made from a valid entrypoint
     */
    function _requireFromEntryPoint() internal view virtual {
        require(msg.sender == address(entryPoint), "Sender not EntryPoint");
    }
}
