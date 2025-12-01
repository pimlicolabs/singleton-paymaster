// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import {ERC20} from "lib/openzeppelin-contracts-v5.1.0/contracts/token/ERC20/ERC20.sol";

contract MockERC20 is ERC20 {
    constructor() ERC20("MockERC20", "MC20") {}

    function mint(address sender, uint256 amount) external {
        _mint(sender, amount);
    }
}
