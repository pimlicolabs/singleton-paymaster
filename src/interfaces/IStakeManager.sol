// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

/**
 * Manage stakes.
 * Stake is value locked for at least "unstakeDelay" by the staked entity.
 */
interface IStakeManager {
    error InvalidUnstakeDelay();
    error StakeTooLow();
    error StakeTooHigh();
    error StakeIsLocked();
    error InsufficientFunds();

    // Emitted when stake or unstake delay are modified.
    event StakeLocked(
        address indexed account,
        address indexed asset,
        uint256 totalStaked,
        uint256 withdrawTime
    );

    event StakeWithdrawn(
        address indexed account,
        address indexed asset,
        address withdrawAddress,
        uint256 amount
    );

    /**
     * @param stake           - Actual amount of ether staked for this entity.
     * @param withdrawTime    - First block timestamp where 'withdrawStake' will be callable, or zero if already locked.
     */
    struct StakeInfo {
        uint128 stake;
        uint128 withdrawTime;
    }

    /**
     * Get stake info.
     * @param account - The account to query.
     * @param asset   - The asset to use.
     * @return info   - Full stake information of given account.
     */
    function getStakeInfo(
        address account,
        address asset
    ) external view returns (StakeInfo memory info);

    /**
     * Get account balance.
     * @param account - The account to query.
     * @param asset   - The asset to use.
     * @return        - The deposit (for gas payment) of the account.
     */
    function balanceOf(
        address account,
        address asset
    ) external view returns (uint256);

    /**
     * Add to the account's stake - amount and delay
     * any pending unstake is first cancelled.
     * @param asset   - The asset to use.
     * @param amount   - The amount of asset to use.
     * @param unstakeDelaySec - The new lock duration before the deposit can be withdrawn.
     */
    function addStake(
        address asset,
        uint128 amount,
        uint32 unstakeDelaySec
    ) external payable;

    /**
     * Withdraw from the stake.
     * @param asset   - The asset to use.
     * @param withdrawAddress - The address to send withdrawn value.
     */
    function withdraw(
        address asset,
        address payable withdrawAddress
    ) external;
}
