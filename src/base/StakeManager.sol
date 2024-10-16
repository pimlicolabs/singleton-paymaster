// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.23;

import "./../interfaces/IStakeManager.sol";
import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";

/* solhint-disable avoid-low-level-calls */
/* solhint-disable not-rely-on-time */

/**
 * Manage deposits and stakes.
 * Deposit is just a balance used to pay for UserOperations (either by a paymaster or an account).
 * Stake is value locked for at least "unstakeDelay" by a paymaster.
 */
abstract contract StakeManager is IStakeManager {
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
    function balanceOf(address account, address asset) public view returns (uint256) {
        return stakes[account][asset].stake;
    }

    receive() external payable {
        addStake(ETH, uint128(msg.value), TWO_WEEKS);
    }

    function _claimStake(
        address account,
        address asset,
        uint128 amount
    ) internal returns (bool) {
        StakeInfo storage info = stakes[account][asset];
        if (info.stake < amount) {
            return false;
        }

        info.stake -= amount;

        emit StakeClaimed(account, asset, amount);

        return true;
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
    ) public payable {
        StakeInfo storage info = stakes[msg.sender][asset];

        uint128 newWithdrawTime = uint128(block.timestamp) + unstakeDelaySec;

        if (unstakeDelaySec == 0 || newWithdrawTime < info.withdrawTime) {
            revert InvalidUnstakeDelay();
        }

        uint256 stake = info.stake + amount;
        if (stake == 0) {
            revert StakeTooLow();
        }

        if (stake > type(uint128).max) {
            revert StakeTooHigh();
        }

        uint256 withdrawTime = block.timestamp + unstakeDelaySec;

        stakes[msg.sender][asset] = StakeInfo(
            uint128(stake),
            uint128(withdrawTime)
        );

        if (asset == ETH) {
            if (msg.value != amount) {
                revert InsufficientFunds();
            }
        } else {
            SafeTransferLib.safeTransferFrom(asset, msg.sender, address(this), amount);
        }

        emit StakeLocked(msg.sender, asset, amount, withdrawTime);
    }

    /**
     * Withdraw from the stake.
     * Must first call unlockStake and wait for the unstakeDelay to pass.
     * @param recipient - The address to send withdrawn value.
     */
    function withdraw(
        address asset,
        address payable recipient
    ) external {
        StakeInfo storage info = stakes[msg.sender][asset];
        uint256 stake = info.stake;

        if (stake == 0) {
            revert StakeTooLow();
        }

        if (info.withdrawTime > block.timestamp) {
            revert StakeIsLocked();
        }

        info.withdrawTime = 0;
        info.stake = 0;

        emit StakeWithdrawn(msg.sender, asset, stake, recipient);

        if (asset == ETH) {
            SafeTransferLib.safeTransferETH(recipient, stake);
        } else {
            SafeTransferLib.safeTransfer(asset, recipient, stake);
        }
    }
}
