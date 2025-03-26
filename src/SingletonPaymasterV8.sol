// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @note EntryPointV8 and EntryPointV7 share the same PackedUserOperation struct.
import { PackedUserOperation } from "@account-abstraction-v7/interfaces/PackedUserOperation.sol";
import { SingletonPaymasterV7 } from "./SingletonPaymasterV7.sol";
import { Eip7702Support } from "./misc/Eip7702Support.sol";

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

    /**
     * @notice Hashses the userOperation data when used in ERC-20 mode.
     * @param _userOp The user operation data.
     * @param _mode The mode that we want to get the hash for.
     * @return bytes32 The hash that the signer should sign over.
     */
    function getHash(uint8 _mode, PackedUserOperation calldata _userOp) public view override returns (bytes32) {
        bytes32 overrideInitCodeHash = Eip7702Support._getEip7702InitCodeHashOverride(_userOp);
        bytes32 originalHash = super.getHash(_mode, _userOp);
        return keccak256(abi.encode(originalHash, overrideInitCodeHash));
    }
}
