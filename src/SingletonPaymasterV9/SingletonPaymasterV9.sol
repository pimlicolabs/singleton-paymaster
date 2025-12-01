// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @custom:note EntryPointV8 and EntryPointV9 share the same PackedUserOperation struct.
import { PackedUserOperation } from "@account-abstraction-v9/interfaces/PackedUserOperation.sol";
import { SingletonPaymaster } from "./SingletonPaymaster.sol";
import { Eip7702Support } from "./misc/Eip7702Support.sol";

/// @title SingletonPaymasterV9
/// @author Pimlico (https://github.com/pimlicolabs/singleton-paymaster/blob/main/src/SingletonPaymasterV9.sol)
/// @author Using Solady (https://github.com/vectorized/solady)
/// @notice An ERC-4337 Paymaster contract that extends SingletonPaymasterV7 where getHash is 7702 aware.
/// @dev Inherits from SingletonPaymasterV7
/// @custom:security-contact security@pimlico.io
contract SingletonPaymasterV9 is SingletonPaymaster {
    constructor(
        address _entryPoint,
        address _owner,
        address _manager,
        address[] memory _signers
    )
        SingletonPaymaster(_entryPoint, _owner, _manager, _signers)
    { }

    /**
     * @notice Get the paymaster hash for the user operation.
     * @param _mode The mode that we want to get the hash for.
     * @param _userOp The user operation.
     * @return bytes32 The hash that the signer should sign over.
     */
    function getHash(uint8 _mode, PackedUserOperation calldata _userOp) public view override returns (bytes32) {
        bytes32 overrideInitCodeHash = Eip7702Support._getEip7702InitCodeHashOverride(_userOp);
        bytes32 originalHash = super.getHash(_mode, _userOp);
        return keccak256(abi.encode(originalHash, overrideInitCodeHash));
    }

    /**
     * @notice For v0.8, the actual penalty is already included in the postOp call.
     * @return uint256 Always returns 0 for V8 paymasters
     */
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
