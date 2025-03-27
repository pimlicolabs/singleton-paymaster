// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import { SingletonPaymasterV7 } from "./SingletonPaymasterV7.sol";

/// @title SingletonPaymasterV8
/// @author Pimlico (https://github.com/pimlicolabs/singleton-paymaster/blob/main/src/SingletonPaymasterV8.sol)
/// @author Using Solady (https://github.com/vectorized/solady)
/// @notice An ERC-4337 Paymaster contract that extends SingletonPaymasterV7 where getHash is 7702 aware.
/// @dev Inherits from SingletonPaymasterV7
/// @custom:security-contact security@pimlico.io
contract SingletonPaymasterV8 is SingletonPaymasterV7 {
    constructor(
        address _entryPoint,
        address _owner,
        address _manager,
        address[] memory _signers
    )
        SingletonPaymasterV7(_entryPoint, _owner, _manager, _signers)
    { }

    function _expectedPenaltyGasCost(
        uint256, /* _actualGasCost */
        uint256, /* _actualUserOpFeePerGas */
        uint128, /* postOpGas */
        uint256, /* preOpGasApproximation */
        uint256 /* executionGasLimit */
    )
        public
        pure
        override
        returns (uint256)
    {
        return 0;
    }
}
