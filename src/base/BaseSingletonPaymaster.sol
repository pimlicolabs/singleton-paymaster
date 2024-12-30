// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/* solhint-disable reason-string */
import { BasePaymaster } from "./BasePaymaster.sol";
import { IPaymasterV6 } from "../interfaces/IPaymasterV6.sol";
import { PostOpMode } from "../interfaces/PostOpMode.sol";
import { MultiSigner } from "./MultiSigner.sol";

import { UserOperation } from "@account-abstraction-v6/interfaces/IPaymaster.sol";
import { UserOperationLib } from "@account-abstraction-v7/core/UserOperationLib.sol";
import { PackedUserOperation } from "@account-abstraction-v7/interfaces/PackedUserOperation.sol";

import { Ownable } from "@openzeppelin-v5.0.2/contracts/access/Ownable.sol";
import { ECDSA } from "@openzeppelin-v5.0.2/contracts/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from "@openzeppelin-v5.0.2/contracts/utils/cryptography/MessageHashUtils.sol";

import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";
import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";

using UserOperationLib for PackedUserOperation;

/// @notice Holds all context needed during the EntryPoint's postOp call.
struct ERC20PostOpContext {
    /// @dev The userOperation sender.
    address sender;
    /// @dev The token used to pay for gas sponsorship.
    address token;
    /// @dev The exchange rate between the token and the chain's native currency.
    uint256 exchangeRate;
    /// @dev The gas overhead when performing the transferFrom call.
    uint128 postOpGas;
    /// @dev The userOperation hash.
    bytes32 userOpHash;
    /// @dev The userOperation's maxFeePerGas (v0.6 only)
    uint256 maxFeePerGas;
    /// @dev The userOperation's maxPriorityFeePerGas (v0.6 only)
    uint256 maxPriorityFeePerGas;
    /// @dev The total allowed execution gas limit, i.e the sum of the callGasLimit and postOpGasLimit.
    uint256 executionGasLimit;
    /// @dev Estimate of the gas used before the userOp is executed.
    uint256 preOpGasApproximation;
}

/// @notice Hold all configs needed in ERC-20 mode.
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
    /// @dev The paymasterValidationGasLimit to be used in the postOp.
    uint128 paymasterValidationGasLimit;
}

/// @title BaseSingletonPaymaster
/// @author Pimlico (https://github.com/pimlicolabs/singleton-paymaster/blob/main/src/base/BaseSingletonPaymaster.sol)
/// @notice Helper class for creating a singleton paymaster.
/// @dev Inherits from BasePaymaster.
/// @dev Inherits from MultiSigner.
abstract contract BaseSingletonPaymaster is Ownable, BasePaymaster, MultiSigner {
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
    /// @dev We need to throw with params due to this bug in EntryPoint v0.6:
    /// https://github.com/eth-infinitism/account-abstraction/pull/293
    error PostOpTransferFromFailed(string msg);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           EVENTS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

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

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  CONSTANTS AND IMMUTABLES                  */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Mode indicating that the Paymaster is in Verifying mode.
    uint8 immutable VERIFYING_MODE = 0;

    /// @notice Mode indicating that the Paymaster is in ERC-20 mode.
    uint8 immutable ERC20_MODE = 1;

    /// @notice The length of the ERC-20 config without singature.
    uint8 immutable ERC20_PAYMASTER_DATA_LENGTH = 96;

    /// @notice The length of the verfiying config without singature.
    uint8 immutable VERIFYING_PAYMASTER_DATA_LENGTH = 12;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          STORAGE                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Address where all ERC-20 tokens will be sent to.
    address public treasury;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        CONSTRUCTOR                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @notice Initializes a SingletonPaymaster instance.
     * @param _entryPoint The entryPoint address.
     * @param _owner The initial contract owner.
     */
    constructor(
        address _entryPoint,
        address _owner,
        address[] memory _signers
    )
        BasePaymaster(_entryPoint, _owner)
        MultiSigner(_signers)
    {
        treasury = _owner;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      ADMIN FUNCTIONS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function setTreasury(address _treasury) public onlyOwner {
        emit TreasuryUpdated(treasury, _treasury);
        treasury = _treasury;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      INTERNAL HELPERS                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @notice Parses the userOperation's paymasterAndData field and returns the paymaster mode and encoded paymaster
     * configuration bytes.
     * @dev _paymasterDataOffset should have value 20 for V6 and 52 for V7.
     * @param _paymasterAndData The paymasterAndData to parse.
     * @param _paymasterDataOffset The paymasterData offset in paymasterAndData.
     * @return mode The paymaster mode.
     * @return paymasterConfig The paymaster config bytes.
     */
    function _parsePaymasterAndData(
        bytes calldata _paymasterAndData,
        uint256 _paymasterDataOffset
    )
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
        if (_paymasterConfig.length < ERC20_PAYMASTER_DATA_LENGTH) {
            revert PaymasterConfigLengthInvalid();
        }

        uint48 validUntil = uint48(bytes6(_paymasterConfig[0:6]));
        uint48 validAfter = uint48(bytes6(_paymasterConfig[6:12]));
        address token = address(bytes20(_paymasterConfig[12:32]));
        uint128 postOpGas = uint128(bytes16(_paymasterConfig[32:48]));
        uint256 exchangeRate = uint256(bytes32(_paymasterConfig[48:80]));
        uint128 paymasterValidationGasLimit = uint128(bytes16(_paymasterConfig[80:96]));
        bytes calldata signature = _paymasterConfig[96:];

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
            signature: signature,
            paymasterValidationGasLimit: paymasterValidationGasLimit
        });

        return config;
    }

    /**
     * @notice Parses the paymaster configuration when used in verifying mode.
     * @param _paymasterConfig The paymaster configuration in bytes.
     * @return validUntil The timestamp until which the sponsorship is valid.
     * @return validAfter The timestamp after which the sponsorship is valid.
     * @return signature The signature over the hashed sponsorship fields.
     * @dev The function reverts if the configuration length is invalid or if the signature length is not 64 or 65
     * bytes.
     */
    function _parseVerifyingConfig(
        bytes calldata _paymasterConfig
    )
        internal
        pure
        returns (uint48, uint48, bytes calldata)
    {
        if (_paymasterConfig.length < VERIFYING_PAYMASTER_DATA_LENGTH) {
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
     * @notice Helper function to encode the postOp context data for V6 userOperations.
     * @param _userOp The userOperation.
     * @param _userOpHash The userOperation hash.
     * @param _cfg The paymaster configuration.
     * @return bytes memory The encoded context.
     */
    function _createPostOpContext(
        UserOperation calldata _userOp,
        bytes32 _userOpHash,
        ERC20PaymasterData memory _cfg
    )
        internal
        pure
        returns (bytes memory)
    {
        address _token = _cfg.token;
        uint256 _exchangeRate = _cfg.exchangeRate;
        uint128 _postOpGas = _cfg.postOpGas;

        return abi.encode(
            ERC20PostOpContext({
                sender: _userOp.sender,
                token: _token,
                exchangeRate: _exchangeRate,
                postOpGas: _postOpGas,
                userOpHash: _userOpHash,
                maxFeePerGas: _userOp.maxFeePerGas,
                maxPriorityFeePerGas: _userOp.maxPriorityFeePerGas,
                preOpGasApproximation: uint256(0), // for v0.6 userOperations, we don't need this due to no penalty.
                executionGasLimit: uint256(0)
            })
        );
    }

    /**
     * @notice Helper function to encode the postOp context data for V7 userOperations.
     * @param _userOp The userOperation.
     * @param _userOpHash The userOperation hash.
     * @param _cfg The paymaster configuration.
     * @return bytes memory The encoded context.
     */
    function _createPostOpContext(
        PackedUserOperation calldata _userOp,
        bytes32 _userOpHash,
        ERC20PaymasterData memory _cfg
    )
        internal
        pure
        returns (bytes memory)
    {
        address _token = _cfg.token;
        uint256 _exchangeRate = _cfg.exchangeRate;
        uint128 _postOpGas = _cfg.postOpGas;
        uint128 _paymasterValidationGasLimit = _cfg.paymasterValidationGasLimit;

        // the limit we have for executing the userOp.
        uint256 executionGasLimit = _userOp.unpackCallGasLimit() + _userOp.unpackPostOpGasLimit();

        // the limit we are allowed for everything before the userOp is executed.
        uint256 preOpGasApproximation = _userOp.preVerificationGas + _userOp.unpackVerificationGasLimit() // VerificationGasLimit
            // is an overestimation.
            + _paymasterValidationGasLimit; // paymasterValidationGasLimit has to be an under estimation to compensate for
            // the overestimation.

        return abi.encode(
            ERC20PostOpContext({
                sender: _userOp.sender,
                token: _token,
                exchangeRate: _exchangeRate,
                postOpGas: _postOpGas,
                userOpHash: _userOpHash,
                maxFeePerGas: uint256(0), // for v0.7 userOperations, the gasPrice is passed in the postOp.
                maxPriorityFeePerGas: uint256(0), // for v0.7 userOperations, the gasPrice is passed in the postOp.
                executionGasLimit: executionGasLimit,
                preOpGasApproximation: preOpGasApproximation
            })
        );
    }

    function _parsePostOpContext(
        bytes calldata _context
    )
        internal
        pure
        returns (address, address, uint256, uint128, bytes32, uint256, uint256, uint256, uint256)
    {
        ERC20PostOpContext memory ctx = abi.decode(_context, (ERC20PostOpContext));

        return (
            ctx.sender,
            ctx.token,
            ctx.exchangeRate,
            ctx.postOpGas,
            ctx.userOpHash,
            ctx.maxFeePerGas,
            ctx.maxPriorityFeePerGas,
            ctx.preOpGasApproximation,
            ctx.executionGasLimit
        );
    }

    /**
     * @notice Gets the cost in amount of tokens.
     * @param _actualGas The gas consumed by the userOperation.
     * @param _postOpGas The gas overhead of transfering the ERC-20 when making the postOp payment.
     * @param _actualUserOpFeePerGas The actual gas cost of the userOperation.
     * @param _exchangeRate The token exchange rate - how many tokens one full ETH (1e18 wei) is worth.
     * @return uint256 The gasCost in token units.
     */
    function getCostInToken(
        uint256 _actualGas,
        uint256 _postOpGas,
        uint256 _actualUserOpFeePerGas,
        uint256 _exchangeRate
    )
        public
        pure
        returns (uint256)
    {
        return ((_actualGas + _postOpGas) * _actualUserOpFeePerGas * _exchangeRate) / 1e18;
    }
}
