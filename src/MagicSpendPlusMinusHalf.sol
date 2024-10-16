// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {UserOperation} from "@account-abstraction-v6/interfaces/IPaymaster.sol";
import {IEntryPoint} from "@account-abstraction-v6/interfaces/IEntryPoint.sol";
import {_packValidationData} from "@account-abstraction-v6/core/Helpers.sol";

import {IERC20} from "@openzeppelin-v5.0.2/contracts/token/ERC20/IERC20.sol";
import {ECDSA} from "@openzeppelin-v5.0.2/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin-v5.0.2/contracts/utils/cryptography/MessageHashUtils.sol";
import {Math} from "@openzeppelin-v5.0.2/contracts/utils/math/Math.sol";
import {Ownable} from "@openzeppelin-v5.0.2/contracts/access/Ownable.sol";

import {MultiSigner} from "./base/MultiSigner.sol";
import {StakeManager} from "./base/StakeManager.sol";
import {NonceManager} from "./base/NonceManager.sol";

import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";

/// @notice Helper struct that represents a call to make.
struct CallStruct {
    address to;
    uint256 value;
    bytes data;
}

/// @notice Signed withdraw request allowing users to withdraw funds from the paymaster's EntryPoint deposit.
struct WithdrawRequest {
    /// @dev Asset that user wants to withdraw.
    address asset;
    /// @dev The requested amount to withdraw.
    uint128 amount;
    /// @dev Unique nonce used to prevent replays.
    uint256 nonce;
    /// @dev Chain id of the network.
    uint256 chainId;
    /// @dev Address that will receive the funds.
    address recipient;
    /// @dev Calls that will be made before the funds are sent to the user.
    CallStruct[] preCalls;
    /// @dev Calls that will be made after the funds are sent to the user.
    CallStruct[] postCalls;
    /// @dev The time in which the request is valid until.
    uint48 validUntil;
    /// @dev The time in which this request is valid after.
    uint48 validAfter;
}

/// @title MagicSpendPlusMinusHalf
/// @author Pimlico (https://github.com/pimlicolabs/singleton-paymaster/blob/main/src/MagicSpendPlusMinusHalf.sol)
/// @notice Contract that allows users to pull funds from if they provide a valid signed withdrawRequest.
/// @dev Inherits from MultiSigner.
/// @dev Inherits from Ownable.
/// @custom:security-contact security@pimlico.io
contract MagicSpendPlusMinusHalf is Ownable, MultiSigner, NonceManager, StakeManager {
    /// @notice Thrown when the request was submitted past its validUntil.
    error RequestExpired();

    /// @notice Thrown when the request was submitted with an invalid chain id.
    error RequestInvlidChain();

    /// @notice Thrown when the request was submitted before its validAfter.
    error RequestNotYetValid();

    /// @notice The withdraw request was initiated with a invalid nonce.
    error SignatureInvalid();

    /// @notice The withdraw request was initiated with a invalid nonce.
    /// @param nonce The nonce used in the withdraw request.
    error NonceInvalid(uint256 nonce);

    /// @notice One of the precalls reverted.
    /// @param revertReason The revert bytes.
    error PreCallReverted(bytes revertReason);

    /// @notice One of the postcalls reverted.
    /// @param revertReason The revert bytes.
    error PostCallReverted(bytes revertReason);

    /// @notice Emitted when a withdraw request has been fulfilled.
    event WithdrawRequestFulfilled(
        bytes32 indexed requestHash,
        address indexed account,
        address indexed asset,
        uint256 amount,
        address recipient,
        uint256 nonce
    );

    /// @notice Mappings keeping track of already used nonces per user to prevent replays of withdraw requests.
    mapping(address user => mapping(uint256 nonce => bool used)) public nonceUsed;

    constructor(address _owner, address[] memory _signers) Ownable(_owner) MultiSigner(_signers) {}

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     EXTERNAL FUNCTIONS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @notice Fulfills a withdraw request only if it has a valid signature and passes validation.
     */
    function requestWithdraw(
        WithdrawRequest calldata withdrawRequest,
        bytes memory accountSignature,
        bytes memory signature
    ) external {
        if (withdrawRequest.chainId != block.chainid) {
            revert RequestInvlidChain();
        }

        if (block.timestamp > withdrawRequest.validUntil && withdrawRequest.validUntil != 0) {
            revert RequestExpired();
        }

        if (block.timestamp < withdrawRequest.validAfter && withdrawRequest.validAfter != 0) {
            revert RequestNotYetValid();
        }

        // check signatures
        bytes32 hash_ = getHash(withdrawRequest);

        // - derive account from the signature
        address account = ECDSA.recover(hash_, accountSignature);

        // - check signature is authorized
        address signer = ECDSA.recover(hash_, signature);

        if (!signers[signer]) {
            revert SignatureInvalid();
        }

        // check withdraw request params
        if (nonceUsed[account][withdrawRequest.nonce]) {
            revert NonceInvalid(withdrawRequest.nonce);
        }

        // Check that the account has enough stake
        bool stakeClaimed = _claimStake(
            account,
            withdrawRequest.asset,
            withdrawRequest.amount
        );

        if (!stakeClaimed) {
            if (withdrawRequest.asset == ETH) {
                revert SafeTransferLib.ETHTransferFailed();
            } else {
                revert SafeTransferLib.TransferFailed();
            }
        }

        // run pre calls
        for (uint256 i = 0; i < withdrawRequest.preCalls.length; i++) {
            address to = withdrawRequest.preCalls[i].to;
            uint256 value = withdrawRequest.preCalls[i].value;
            bytes memory data = withdrawRequest.preCalls[i].data;

            (bool success, bytes memory result) = to.call{value: value}(data);

            if (!success) {
                revert PreCallReverted(result);
            }
        }

        // fulfil withdraw request
        if (withdrawRequest.asset == address(0)) {
            SafeTransferLib.forceSafeTransferETH(withdrawRequest.recipient, withdrawRequest.amount);
        } else {
            SafeTransferLib.safeTransfer(withdrawRequest.asset, withdrawRequest.recipient, withdrawRequest.amount);
        }

        // run postcalls
        for (uint256 i = 0; i < withdrawRequest.postCalls.length; i++) {
            address to = withdrawRequest.postCalls[i].to;
            uint256 value = withdrawRequest.postCalls[i].value;
            bytes memory data = withdrawRequest.postCalls[i].data;

            (bool success, bytes memory result) = to.call{value: value}(data);

            if (!success) {
                revert PostCallReverted(result);
            }
        }

        nonceUsed[account][withdrawRequest.nonce] = true;

        emit WithdrawRequestFulfilled(
            hash_,
            account,
            withdrawRequest.asset,
            withdrawRequest.amount,
            withdrawRequest.recipient,
            withdrawRequest.nonce
        );
    }

    /**
     * @notice Allows the caller to withdraw funds if a valid signature is passed.
     * @dev At time of call, recipient will be equal to msg.sender.
     * @param withdrawRequest The withdraw request to get the hash of.
     * @return The hashed withdraw request.
     */
    function getHash(WithdrawRequest calldata withdrawRequest) public view returns (bytes32) {
        bytes32 digest = keccak256(
            abi.encode(
                address(this),
                block.chainid,
                withdrawRequest.asset,
                withdrawRequest.amount,
                withdrawRequest.recipient,
                withdrawRequest.nonce,
                withdrawRequest.chainId,
                withdrawRequest.validUntil,
                withdrawRequest.validAfter,
                keccak256(abi.encode(withdrawRequest.preCalls)),
                keccak256(abi.encode(withdrawRequest.postCalls))
            )
        );

        return MessageHashUtils.toEthSignedMessageHash(digest);
    }
}
