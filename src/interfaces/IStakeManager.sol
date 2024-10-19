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

    enum StakeUpdateEvent {
        ADDED,
        UNSTAKED,
        CLAIMED
    }

    event StakeUpdated(
        StakeUpdateEvent event_,
        address indexed account,
        address indexed asset,
        uint128 amount,
        uint128 withdrawTime
    );

    /**
     * @param stake           - Actual amount of ether staked for this entity.
     * @param unstakeTime    - First block timestamp where 'unstake' will be callable.
     */
    struct StakeInfo {
        uint128 stake;
        uint128 unstakeTime;
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
    function stakeOf(
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
     * @param recipient - The address to send withdrawn value.
     */
    function unstake(
        address asset,
        address payable recipient
    ) external;
}
