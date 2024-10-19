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

/// @notice Request acts as a reciept
/// @dev signed by one of the signers it allows to withdraw funds
/// @dev signed by the user it allows to claim funds from it's stake
struct Request {
    /// @dev Asset that user wants to withdraw.
    address asset;
    /// @dev The requested amount to withdraw.
    uint128 amount;
    /// @dev The amount of fee that will be paid to the operator.
    uint128 fee;
    /// @dev Chain id of the network, where the request will be claimed.
    uint256 claimChainId;
    /// @dev Chain id of the network, where the request will be withdrawn.
    uint256 withdrawChainId;
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
    /// @dev The new unstakeDelaySec for the user after the request is claimed.
    /// @dev If 0, the unstakeDelaySec will not be updated.
    /// @dev Ignored if results in a value lower then the current one.
    uint128 unstakeDelaySec;
}


/// @title MagicSpendPlusMinusHalf
/// @author Pimlico (https://github.com/pimlicolabs/singleton-paymaster/blob/main/src/MagicSpendPlusMinusHalf.sol)
/// @notice Contract that allows users to pull funds from if they provide a valid signed request.
/// @dev Inherits from MultiSigner.
/// @dev Inherits from Ownable.
/// @custom:security-contact security@pimlico.io
contract MagicSpendPlusMinusHalf is Ownable, MultiSigner, NonceManager, StakeManager {
    /// @notice Thrown when the request was submitted past its validUntil.
    error RequestExpired();

    /// @notice Thrown when the request was submitted with an invalid chain id.
    error RequestInvalidChain();

    /// @notice Thrown when the request was submitted before its validAfter.
    error RequestNotYetValid();

    /// @notice The withdraw request was initiated with a invalid nonce.
    error SignatureInvalid();

    /// @notice The withdraw request was already withdrawn or claimed.
    error AlreadyUsed();

    /// @notice One of the precalls reverted.
    /// @param revertReason The revert bytes.
    error PreCallReverted(bytes revertReason);

    /// @notice One of the postcalls reverted.
    /// @param revertReason The revert bytes.
    error PostCallReverted(bytes revertReason);

    /// @notice Emitted when a withdraw request has been fulfilled.
    event RequestWithdrawn(bytes32 indexed requestHash);

    /// @notice Emitted when a claim request has been fulfilled.
    event RequestClaimed(bytes32 indexed requestHash);

    /// @notice Emitted when a deposit has been made.
    event Deposit(
        address indexed asset,
        uint256 amount
    );

    struct RequestStatus {
        bool withdrawn;
        bool claimed;
    }

    mapping(address asset => uint256 amount) public balances;
    mapping(bytes32 hash_ => RequestStatus status) public statuses;

    constructor(
        address _owner,
        address[] memory _signers
    ) Ownable(_owner) MultiSigner(_signers) {}

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     EXTERNAL FUNCTIONS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @notice Fulfills a withdraw request only if it has a valid signature and passes validation.
     * The signature should be signed by one of the signers.
     */
    function withdraw(
        Request calldata request,
        bytes calldata signature
    ) external {
        if (request.withdrawChainId != block.chainid) {
            revert RequestInvalidChain();
        }

        if (block.timestamp > request.validUntil && request.validUntil != 0) {
            revert RequestExpired();
        }

        if (block.timestamp < request.validAfter && request.validAfter != 0) {
            revert RequestNotYetValid();
        }

        // check signature is authorized by the actual operator
        bytes32 hash_ = getHash(request);

        address signer = ECDSA.recover(
            hash_,
            signature
        );

        if (!signers[signer]) {
            revert SignatureInvalid();
        }

        // check withdraw request params
        if (statuses[hash_].withdrawn) {
            revert AlreadyUsed();
        }

        // run pre calls
        for (uint256 i = 0; i < request.preCalls.length; i++) {
            address to = request.preCalls[i].to;
            uint256 value = request.preCalls[i].value;
            bytes memory data = request.preCalls[i].data;

            (bool success, bytes memory result) = to.call{value: value}(data);

            if (!success) {
                revert PreCallReverted(result);
            }
        }

        // fulfil withdraw request
        if (request.asset == address(0)) {
            SafeTransferLib.forceSafeTransferETH(request.recipient, request.amount);
        } else {
            SafeTransferLib.safeTransfer(request.asset, request.recipient, request.amount);
        }

        // run postcalls
        for (uint256 i = 0; i < request.postCalls.length; i++) {
            address to = request.postCalls[i].to;
            uint256 value = request.postCalls[i].value;
            bytes memory data = request.postCalls[i].data;

            (bool success, bytes memory result) = to.call{value: value}(data);

            if (!success) {
                revert PostCallReverted(result);
            }
        }

        statuses[hash_].withdrawn = true;

        emit RequestWithdrawn(hash_);
    }

    function claim(
        Request calldata request,
        bytes calldata signature
    ) external {
        bytes32 hash_ = getHash(request);

        address account = ECDSA.recover(
            hash_,
            signature
        );

        if (statuses[hash_].claimed) {
            revert AlreadyUsed();
        }

        uint128 amount = request.amount + request.fee;

        _claimStake(
            account,
            request.asset,
            amount,
            request.unstakeDelaySec
        );

        statuses[hash_].claimed = true;

        emit RequestClaimed(
            hash_
        );
    }

    function deposit(
        address asset,
        uint256 amount
    ) external payable {
        if (asset == address(0)) {
            if (msg.value != amount) {
                revert InsufficientFunds();
            }
        } else {
            SafeTransferLib.safeTransferFrom(asset, msg.sender, address(this), amount);
        }

        emit Deposit(
            asset,
            amount
        );
    }

    /**
     * @notice Allows the caller to withdraw funds if a valid signature is passed.
     * @dev At time of call, recipient will be equal to msg.sender.
     * @param request The withdraw request to get the hash of.
     * @return The hashed withdraw request.
     */
    function getHash(Request calldata request) public view returns (bytes32) {
        bytes32 validityDigest = keccak256(abi.encode(request.validUntil, request.validAfter));
        bytes32 callsDigest = keccak256(abi.encode(request.preCalls, request.postCalls));

        bytes32 digest = keccak256(
            abi.encode(
                address(this),
                request.claimChainId,
                request.withdrawChainId,
                request.asset,
                request.amount,
                request.recipient,
                request.withdrawChainId,
                request.claimChainId,
                request.unstakeDelaySec,
                validityDigest,
                callsDigest
            )
        );

        return MessageHashUtils.toEthSignedMessageHash(digest);
    }
}
