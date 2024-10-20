// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.23;

import "./../interfaces/IStakeManager.sol";
import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";
import {ReentrancyGuard} from "@openzeppelin-v5.0.2/contracts/utils/ReentrancyGuard.sol";

/* solhint-disable avoid-low-level-calls */
/* solhint-disable not-rely-on-time */

/**
 * Manages stakes.
 * Stakes are locked for a period of time.
 * Stakes can be added, claimed, and removed.
 * - To add stake, call `addStake` with the asset and amount.
 * - Stake is claimed every time `MagicSpendPlusMinusHalf.claim` is called
 * - To remove stake, call `removeStake` with the asset and recipient. No partical unstakes are allowed.
 */
abstract contract StakeManager is IStakeManager, ReentrancyGuard {
    /// maps account to asset to stake
    mapping(address => mapping(address => StakeInfo)) private stakes;

    uint32 public constant TWO_WEEKS = 1209600;
    address public constant ETH = address(0);

    /// @inheritdoc IStakeManager
    function getStakeInfo(
        address account,
        address asset
    ) public view returns (StakeInfo memory info) {
        return stakes[account][asset];
    }

    /// @inheritdoc IStakeManager
    function stakeOf(address account, address asset) public view returns (uint256) {
        return stakes[account][asset].stake;
    }

    receive() external payable {
        addStake(ETH, uint128(msg.value), TWO_WEEKS);
    }

    /**
     * Add to the account's stake - amount and delay
     * any pending unstake is first cancelled.
     * @param unstakeDelaySec The new lock duration before the deposit can be withdrawn.
     */
    function addStake(
        address asset,
        uint128 amount,
        uint32 unstakeDelaySec
    ) public nonReentrant payable {
        StakeInfo storage info = stakes[msg.sender][asset];

        uint128 unstakeTime = uint128(block.timestamp) + unstakeDelaySec;

        if (unstakeDelaySec == 0 || unstakeTime < info.unstakeTime) {
            revert InvalidUnstakeDelay();
        }

        uint128 stake = info.stake + amount;
        if (stake == 0) {
            revert StakeTooLow();
        }

        if (stake > type(uint128).max) {
            revert StakeTooHigh();
        }

        stakes[msg.sender][asset] = StakeInfo(
            stake,
            unstakeTime
        );

        if (asset == ETH) {
            if (msg.value != amount) {
                revert InsufficientFunds();
            }
        } else {
            SafeTransferLib.safeTransferFrom(asset, msg.sender, address(this), amount);
        }

        emit StakeUpdated(
            StakeUpdateEvent.ADDED,
            msg.sender,
            asset,
            amount,
            stake,
            unstakeTime
        );
    }

    function _claimStake(
        address account,
        address asset,
        uint128 amount,
        uint128 newUnstakeDelaySec
    ) internal {
        StakeInfo storage info = stakes[account][asset];
        uint128 stake = info.stake;

        if (stake < amount) {
            revert StakeTooLow();
        }

        info.stake = stake - amount;

        uint128 unstakeTime = info.unstakeTime;

        if (newUnstakeDelaySec != 0) {
            uint128 newUnstakeTime = uint128(block.timestamp) + newUnstakeDelaySec;

            if (newUnstakeTime > unstakeTime) {
                info.unstakeTime = newUnstakeTime;
            }
        }

        emit StakeUpdated(
            StakeUpdateEvent.CLAIMED,
            account,
            asset,
            amount,
            info.stake,
            info.unstakeTime
        );
    }

    /**
     * Remove the stake.
     * @param asset     - The asset to remove.
     * @param recipient - The address to send removed value.
     */
    function removeStake(
        address asset,
        address payable recipient
    ) external nonReentrant {
        StakeInfo storage info = stakes[msg.sender][asset];
        uint128 stake = info.stake;

        if (stake == 0) {
            revert StakeTooLow();
        }

        if (info.unstakeTime > block.timestamp) {
            revert StakeIsLocked();
        }

        info.unstakeTime = 0;
        info.stake = 0;

        if (asset == ETH) {
            SafeTransferLib.safeTransferETH(recipient, stake);
        } else {
            SafeTransferLib.safeTransfer(asset, recipient, stake);
        }

        emit StakeUpdated(
            StakeUpdateEvent.REMOVED,
            msg.sender,
            asset,
            stake,
            0,
            0
        );
    }
}
