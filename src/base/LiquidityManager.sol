// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";
import {Ownable} from "@openzeppelin-v5.0.2/contracts/access/Ownable.sol";


abstract contract LiquidityManager is Ownable {
    error InsufficientLiquidity(address asset);

    enum LiquidityUpdateEvent {
        ADDED,
        REMOVED
    }

    /// @notice Emitted when liquidity has been added or removed.
    event LiquidityUpdated(
        LiquidityUpdateEvent event_,
        address indexed asset,
        uint128 diff,
        uint128 amount
    );

    mapping (address asset => uint128 amount) private liquidity;

    function getBalance(address asset) public view returns (uint128) {
        return liquidity[asset];
    }

    function addLiquidity(
        address asset,
        uint128 amount
    ) external payable {
        if (asset == address(0)) {
            if (msg.value != amount) {
                revert InsufficientLiquidity(asset);
            }
        } else {
            SafeTransferLib.safeTransferFrom(asset, msg.sender, address(this), amount);
        }

        _addLiquidity(asset, amount);

        emit LiquidityUpdated(
            LiquidityUpdateEvent.ADDED,
            asset,
            amount,
            liquidity[asset]
        );
    }

    function removeLiquidity(
        address asset,
        uint128 amount
    ) external onlyOwner {
        _removeLiquidity(asset, amount);

        if (asset == address(0)) {
            SafeTransferLib.forceSafeTransferETH(msg.sender, amount);
        } else {
            SafeTransferLib.safeTransfer(asset, msg.sender, amount);
        }

        emit LiquidityUpdated(
            LiquidityUpdateEvent.REMOVED,
            asset,
            amount,
            liquidity[asset]
        );
    }

    function _addLiquidity(
        address asset,
        uint128 amount
    ) internal {
        liquidity[asset] += amount;
    }

    function _removeLiquidity(
        address asset,
        uint128 amount
    ) internal {
        if (liquidity[asset] < amount) {
            revert InsufficientLiquidity(asset);
        }

        liquidity[asset] -= amount;
    }
}