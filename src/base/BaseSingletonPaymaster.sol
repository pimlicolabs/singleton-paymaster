// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/* solhint-disable reason-string */
import {BasePaymaster} from "./BasePaymaster.sol";
import {IPaymasterV6} from "../interfaces/IPaymasterV6.sol";
import {PostOpMode} from "../interfaces/PostOpMode.sol";

import {UserOperation} from "@account-abstraction-v6/interfaces/IPaymaster.sol";
import {PackedUserOperation} from "@account-abstraction-v7/interfaces/PackedUserOperation.sol";

import {Ownable} from "@openzeppelin-v5.0.0/contracts/access/Ownable.sol";
import {ECDSA} from "@openzeppelin-v5.0.0/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin-v5.0.0/contracts/utils/cryptography/MessageHashUtils.sol";

import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";
import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";

/// @notice Signed withdraw request allowing users to withdraw funds from the paymaster's EntryPoint deposit.
struct WithdrawRequest {
    /// @dev The receiver of the funds.
    address recipient;
    /// @dev Unique nonce used to prevent replays.
    uint256 nonce;
    /// @dev The requested amount to withdraw.
    uint256 amount;
    /// @dev The maximum expiry the withdraw request remains valid for.
    uint48 expiry;
    /// @dev The signature associated with this withdraw request.
    bytes signature;
}

/// @notice Helper struct to hold all configs needed in ERC-20 mode.
struct ERC20PaymasterData {
    /// @dev Timestamp until which the sponsorship is valid.
    uint48 validUntil;
    /// @dev Timestamp after which the sponsorship is valid.
    uint48 validAfter;
    /// @dev The gas overhead of calling transferFrom during the postOp.
    uint128 postOpGas;
    /// @dev ERC-20 token that the sender will pay with.
    address token;
    /// @dev The exchange rate of the ERC-20 token during sponsorship.
    uint256 exchangeRate;
    /// @dev The paymaster signature.
    bytes signature;
}

/// @title BaseSingletonPaymaster
/// @author Pimlico (https://github.com/pimlicolabs/singleton-paymaster/blob/main/src/base/BaseSingletonPaymaster.sol)
/// @notice Helper class for creating a singleton paymaster.
/// @dev Inherits from BasePaymaster.
abstract contract BaseSingletonPaymaster is Ownable, BasePaymaster {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CUSTOM ERRORS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice The paymaster data length is invalid.
    error PaymasterAndDataLengthInvalid();

    /// @notice The paymaster data mode is invalid. The mode should be 0 or 1.
    error PaymasterModeInvalid();

    /// @notice The paymaster data length is invalid for the selected mode.
    error PaymasterConfigLengthInvalid();

    /// @notice The paymaster signature length is invalid.
    error PaymasterSignatureLengthInvalid();

    /// @notice The token is invalid.
    error TokenAddressInvalid();

    /// @notice The token exchange rate is invalid.
    error ExchangeRateInvalid();

    /// @notice The payment failed due to the TransferFrom call in the PostOp reverting.
    /// @dev We need to throw with params due to this bug in EntryPoint v0.6: https://github.com/eth-infinitism/account-abstraction/pull/293
    error PostOpTransferFromFailed(string msg);

    /// @notice The withdraw request's expiry has been reached.
    error WithdrawRequestExpired();

    /// @notice The withdraw request was initiated with a invalid nonce.
    error WithdrawSignatureInvalid();

    /// @notice The withdraw request was initiated with a invalid nonce.
    /// @param nonce The nonce used in the withdraw request.
    error WithdrawNonceInvalid(uint256 nonce);

    /// @notice Thrown if is larger than paymaster.getDeposit() - WithdrawRequest.amount < paymasterMinBalance.
    /// @param requestedAmount The requested withdraw amount.
    /// @param maxAllowed      The current max allowed withdraw.
    error WithdrawTooLarge(uint256 requestedAmount, uint256 maxAllowed);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           EVENTS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Emitted when a withdraw request was successfully fulfilled.
    event WithdrawRequestFulfilled(
        address indexed receiver,
        /// @param The value withdrawn by the user.
        uint256 value,
        /// @param The nonce used to fulfil this withdraw request.
        uint256 nonce
    );

    /// @dev Emitted when a user operation is sponsored by the paymaster.
    event UserOperationSponsored(
        bytes32 indexed userOpHash,
        /// @param The user that requested sponsorship.
        address indexed user,
        /// @param The paymaster mode that was used.
        uint8 paymasterMode,
        /// @param The token that was used during sponsorship (ERC-20 mode only).
        address token,
        /// @param The amount of token paid during sponsorship (ERC-20 mode only).
        uint256 tokenAmountPaid,
        /// @param The exchange rate of the token at time of sponsorship (ERC-20 mode only).
        uint256 exchangeRate
    );

    /// @notice Emitted when a new treasury is set.
    event TreasuryUpdated(address oldTreasury, address newTreasury);

    /// @notice Emitted when a signer is added.
    event SignerAdded(address signer);

    /// @notice Emitted when a signer is removed.
    event SignerRemoved(address signer);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          STORAGE                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Mapping of valid signers.
    /// @dev No signers are initialized at the time of contract creation.
    mapping(address account => bool isValidSigner) public signers;

    /// @notice Address where all ERC-20 tokens will be sent to.
    address public treasury;

    /// @notice Ensures the paymaster maintains a minimum balance to ensure continued operation.
    uint256 public paymasterMinBalance;

    /// @notice Mappings keeping track of already used nonces per user to prevent replays of withdraw requests.
    mapping(address user => mapping(uint256 nonce => bool used)) public nonceUsed;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        CONSTRUCTOR                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @notice Initializes a SingletonPaymaster instance.
     * @param _entryPoint The entryPoint address.
     * @param _owner The initial contract owner.
     */
    constructor(address _entryPoint, address _owner) BasePaymaster(_entryPoint, _owner) {
        treasury = _owner;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      ADMIN FUNCTIONS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function removeSigner(address _signer) public onlyOwner {
        signers[_signer] = false;
        emit SignerRemoved(_signer);
    }

    function addSigner(address _signer) public onlyOwner {
        signers[_signer] = true;
        emit SignerAdded(_signer);
    }

    function setTreasury(address _treasury) public onlyOwner {
        emit TreasuryUpdated(treasury, _treasury);
        treasury = _treasury;
    }

    function setPaymasterMinBalance(uint256 _minBalance) public onlyOwner {
        paymasterMinBalance = _minBalance;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     EXTERNAL FUNCTIONS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @notice Fulfills a withdraw request only if it passes validation and has a valid signature.
     */
    function requestWithdraw(WithdrawRequest calldata withdrawRequest) external {
        if (block.timestamp > withdrawRequest.expiry) {
            revert WithdrawRequestExpired();
        }

        // check signature
        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(getWithdrawHash(withdrawRequest));
        address recoveredSigner = ECDSA.recover(hash, withdrawRequest.signature);

        if (!signers[recoveredSigner]) {
            revert WithdrawSignatureInvalid();
        }

        // check withdraw request params
        if (nonceUsed[withdrawRequest.recipient][withdrawRequest.nonce]) {
            revert WithdrawNonceInvalid(withdrawRequest.nonce);
        }

        uint256 maxAllowedWithdraw = getDeposit() - paymasterMinBalance;
        if (withdrawRequest.amount > maxAllowedWithdraw) {
            revert WithdrawTooLarge(withdrawRequest.amount, maxAllowedWithdraw);
        }

        nonceUsed[withdrawRequest.recipient][withdrawRequest.nonce] = true;
        entryPoint.withdrawTo(payable(withdrawRequest.recipient), withdrawRequest.amount);
        emit WithdrawRequestFulfilled(withdrawRequest.recipient, withdrawRequest.amount, withdrawRequest.nonce);
    }

    /**
     * @notice Allows the caller to withdraw funds if a valid signature is passed.
     * @param withdrawRequest The withdraw request to get the hash of.
     * @return The hashed withdraw request.
     */
    function getWithdrawHash(WithdrawRequest calldata withdrawRequest) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                address(this),
                block.chainid,
                withdrawRequest.recipient,
                withdrawRequest.amount,
                withdrawRequest.nonce,
                withdrawRequest.expiry
            )
        );
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      INTERNAL HELPERS                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @notice Parses the userOperation's paymasterAndData field and returns the paymaster mode and encoded paymaster configuration bytes.
     * @dev _paymasterDataOffset should have value 20 for V6 and 52 for V7.
     * @param _paymasterAndData The paymasterAndData to parse.
     * @param _paymasterDataOffset The paymasterData offset in paymasterAndData.
     * @return mode The paymaster mode.
     * @return paymasterConfig The paymaster config bytes.
     */
    function _parsePaymasterAndData(bytes calldata _paymasterAndData, uint256 _paymasterDataOffset)
        internal
        pure
        returns (uint8, bytes calldata)
    {
        if (_paymasterAndData.length < _paymasterDataOffset + 1) {
            revert PaymasterAndDataLengthInvalid();
        }

        uint8 mode = uint8(bytes1(_paymasterAndData[_paymasterDataOffset:_paymasterDataOffset + 1]));
        bytes calldata paymasterConfig = _paymasterAndData[_paymasterDataOffset + 1:];

        return (mode, paymasterConfig);
    }

    /**
     * @notice Parses the paymaster configuration when used in ERC-20 mode.
     * @param _paymasterConfig The paymaster configuration in bytes.
     * @return ERC20PaymasterData The parsed paymaster configuration values.
     */
    function _parseErc20Config(bytes calldata _paymasterConfig) internal pure returns (ERC20PaymasterData memory) {
        if (_paymasterConfig.length < 64) {
            revert PaymasterConfigLengthInvalid();
        }

        uint48 validUntil = uint48(bytes6(_paymasterConfig[0:6]));
        uint48 validAfter = uint48(bytes6(_paymasterConfig[6:12]));
        address token = address(bytes20(_paymasterConfig[12:32]));
        uint128 postOpGas = uint128(bytes16(_paymasterConfig[32:48]));
        uint256 exchangeRate = uint256(bytes32(_paymasterConfig[48:80]));
        bytes calldata signature = _paymasterConfig[80:];

        if (token == address(0)) {
            revert TokenAddressInvalid();
        }

        if (exchangeRate == 0) {
            revert ExchangeRateInvalid();
        }

        if (signature.length != 64 && signature.length != 65) {
            revert PaymasterSignatureLengthInvalid();
        }

        ERC20PaymasterData memory config = ERC20PaymasterData({
            validUntil: validUntil,
            validAfter: validAfter,
            token: token,
            exchangeRate: exchangeRate,
            postOpGas: postOpGas,
            signature: signature
        });

        return config;
    }

    /**
     * @notice Parses the paymaster configuration when used in verifying mode.
     * @param _paymasterConfig The paymaster configuration in bytes.
     * @return validUntil The timestamp until which the sponsorship is valid.
     * @return validAfter The timestamp after which the sponsorship is valid.
     * @return signature The signature over the hashed sponsorship fields.
     * @dev The function reverts if the configuration length is invalid or if the signature length is not 64 or 65 bytes.
     */
    function _parseVerifyingConfig(bytes calldata _paymasterConfig)
        internal
        pure
        returns (uint48, uint48, bytes calldata)
    {
        if (_paymasterConfig.length < 12) {
            revert PaymasterConfigLengthInvalid();
        }

        uint48 validUntil = uint48(bytes6(_paymasterConfig[0:6]));
        uint48 validAfter = uint48(bytes6(_paymasterConfig[6:12]));
        bytes calldata signature = _paymasterConfig[12:];

        if (signature.length != 64 && signature.length != 65) {
            revert PaymasterSignatureLengthInvalid();
        }

        return (validUntil, validAfter, signature);
    }

    /**
     * @notice Helper function to parse the postOp context.
     * @dev returned values for maxFeePerGas and maxPriorityFeePerGas are always zero in V7.
     * @param _context The encoded context.
     * @return address The sender.
     * @return address The ERC-20 token.
     * @return uint256 The token exchange rate.
     * @return uint256 The postOp gas.
     * @return bytes32 The userOperation hash.
     * @return uint256 The maxFeePerGas (V6 only).
     * @return uint256 The maxPriorityFeePerGas (V6 only).
     */
    function _parsePostOpContext(bytes calldata _context)
        internal
        pure
        returns (address, address, uint256, uint128, bytes32, uint256, uint256)
    {
        uint256 maxFeePerGas = 0;
        uint256 maxPriorityFeePerGas = 0;

        // parsing bytes from right to left to avoid stack too deep
        {
            if (_context.length == 184) {
                maxPriorityFeePerGas = uint256(bytes32(_context[152:184]));
                maxFeePerGas = uint256(bytes32(_context[120:152]));
            }
        }

        bytes32 userOpHash = bytes32(_context[88:120]);
        uint128 postOpGas = uint128(bytes16(_context[72:88]));
        uint256 exchangeRate = uint256(bytes32(_context[40:72]));
        address token = address(bytes20(_context[20:40]));
        address sender = address(bytes20(_context[0:20]));

        return (sender, token, exchangeRate, postOpGas, userOpHash, maxFeePerGas, maxPriorityFeePerGas);
    }

    /**
     * @notice Helper function to encode the postOp context data for V6 userOperations.
     * @param _userOp The userOperation.
     * @param _exchangeRate The token exchange rate.
     * @param _postOpGas The gas to cover the overhead of the postOp transferFrom call.
     * @param _userOpHash The userOperation hash.
     * @return bytes memory The encoded context.
     */
    function _createPostOpContext(
        UserOperation calldata _userOp,
        address _token,
        uint256 _exchangeRate,
        uint128 _postOpGas,
        bytes32 _userOpHash
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            _userOp.sender,
            _token,
            _exchangeRate,
            _postOpGas,
            _userOpHash,
            _userOp.maxFeePerGas,
            _userOp.maxPriorityFeePerGas
        );
    }

    /**
     * @notice Helper function to encode the postOp context data for V7 userOperations.
     * @param _userOp The userOperation.
     * @param _exchangeRate The token exchange rate.
     * @param _postOpGas The gas to cover the overhead of the transferFrom call.
     * @param _userOpHash The userOperation hash.
     * @return bytes memory The encoded context.
     */
    function _createPostOpContext(
        PackedUserOperation calldata _userOp,
        address _token,
        uint256 _exchangeRate,
        uint128 _postOpGas,
        bytes32 _userOpHash
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(_userOp.sender, _token, _exchangeRate, _postOpGas, _userOpHash, uint256(0), uint256(0));
    }

    /**
     * @notice Gets the cost in amount of tokens.
     * @param _actualGasCost The gas consumed by the userOperation.
     * @param _postOpGas The gas overhead of transfering the ERC-20 when making the postOp payment.
     * @param _actualUserOpFeePerGas The actual gas cost of the userOperation.
     * @param _exchangeRate The exchange rate of the token (in wei).
     * @return uint256 The gasCost in token units.
     */
    function getCostInToken(
        uint256 _actualGasCost,
        uint256 _postOpGas,
        uint256 _actualUserOpFeePerGas,
        uint256 _exchangeRate
    ) public pure returns (uint256) {
        return ((_actualGasCost + (_postOpGas * _actualUserOpFeePerGas)) * _exchangeRate) / 1e18;
    }
}
