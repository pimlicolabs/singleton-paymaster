// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/* solhint-disable reason-string */

import {Ownable} from "@openzeppelin-v5.0.2/contracts/access/Ownable.sol";
import {IERC165} from "@openzeppelin-v5.0.2/contracts/utils/introspection/IERC165.sol";
import {IEntryPoint} from "@account-abstraction-v7/interfaces/IEntryPoint.sol";

/**
 * Helper class for creating a contract with signer.
 */
abstract contract Signer is Ownable {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           EVENTS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Emitted when a signer is added.
    event SignerAdded(address signer);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          STORAGE                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Signer address.
    address private signer;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CONSTRUCTOR                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    constructor(address _signer) {
        _addSigner(_signer);
    }

    function _isSigner(address _signer) internal view returns (bool) {
        return signer == _signer;
    }

    function getSigner() public view returns (address) {
        return signer;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      ADMIN FUNCTIONS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function addSigner(address _signer) public onlyOwner {
        _addSigner(_signer);
    }

    function _addSigner(address _signer) internal {
        signer = _signer;

        emit SignerAdded(_signer);
    }
}
