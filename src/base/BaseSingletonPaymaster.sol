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
    /// @dev The treasury address where the tokens will be sent to.
    address treasury;
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
    /// @dev A constant fee that is added to the userOp's gas cost.
    uint128 constantFee;
}

/// @notice Hold all configs needed in ERC-20 mode.
struct ERC20PaymasterData {
    /// @dev The treasury address where the tokens will be sent to.
    address treasury;
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
    /// @dev A constant fee that is added to the userOp's gas cost.
    uint128 constantFee;
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

    /// @notice Event for changing a bundler allowlist configuration
    ///
    /// @param bundler Address of the bundler
    /// @param allowed True if was allowlisted, false if removed from allowlist
    event BundlerAllowlistUpdated(address bundler, bool allowed);

    /// @notice Error for bundler not allowed
    ///
    /// @param bundler address of the bundler that was not allowlisted
    error BundlerNotAllowed(address bundler);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  CONSTANTS AND IMMUTABLES                  */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Mode indicating that the Paymaster is in Verifying mode.
    uint8 immutable VERIFYING_MODE = 0;

    /// @notice Mode indicating that the Paymaster is in ERC-20 mode.
    uint8 immutable ERC20_MODE = 1;

    /// @notice Mode indicating that the Paymaster is in ERC-20 mode with a constant fee.
    uint8 immutable ERC20_WITH_CONSTANT_FEE_MODE = 2;

    /// @notice The length of the ERC-20 config without singature.
    uint8 immutable ERC20_PAYMASTER_DATA_LENGTH = 118; // 116 + 2 (mode & allowAllBundlers)

    /// @notice The length of the ERC-20 with constant fee config with singature.
    uint8 immutable ERC20_WITH_CONSTANT_FEE_PAYMASTER_DATA_LENGTH = 134; // 116 + 16 (constantFee) + 2 (mode &
        // allowAllBundlers)

    /// @notice The length of the verfiying config without singature.
    uint8 immutable VERIFYING_PAYMASTER_DATA_LENGTH = 14; // 12 + 2 (mode & allowAllBundlers)

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          STORAGE                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Allowlist of bundlers to use if restricting bundlers is enabled by flag
    mapping(address bundler => bool allowed) public isBundlerAllowed;

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
    { }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      ADMIN FUNCTIONS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Add or remove multiple bundlers to/from the allowlist
    ///
    /// @param bundlers Array of bundler addresses
    /// @param allowed Boolean indicating if bundlers should be allowed or not
    function updateBundlerAllowlist(address[] calldata bundlers, bool allowed) external onlyOwner {
        for (uint256 i = 0; i < bundlers.length; i++) {
            isBundlerAllowed[bundlers[i]] = allowed;
            emit BundlerAllowlistUpdated(bundlers[i], allowed);
        }
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
        returns (uint8, bool, bytes calldata)
    {
        if (_paymasterAndData.length < _paymasterDataOffset + 1) {
            revert PaymasterAndDataLengthInvalid();
        }

        uint8 mode = uint8(bytes1(_paymasterAndData[_paymasterDataOffset:_paymasterDataOffset + 1]));
        bool allowAllBundlers = uint8(bytes1(_paymasterAndData[_paymasterDataOffset + 1:_paymasterDataOffset + 2])) == 1;
        bytes calldata paymasterConfig = _paymasterAndData[_paymasterDataOffset + 2:];

        return (mode, allowAllBundlers, paymasterConfig);
    }

    /**
     * @notice Parses the paymaster configuration when used in ERC-20 mode.
     * @param _paymasterConfig The paymaster configuration in bytes.
     * @return ERC20PaymasterData The parsed paymaster configuration values.
     */
    function _parseErc20Config(
        uint8 _mode,
        bytes calldata _paymasterConfig
    )
        internal
        pure
        returns (ERC20PaymasterData memory)
    {
        if (
            _paymasterConfig.length
                < (
                    _mode == ERC20_WITH_CONSTANT_FEE_MODE
                        ? ERC20_WITH_CONSTANT_FEE_PAYMASTER_DATA_LENGTH
                        : ERC20_PAYMASTER_DATA_LENGTH
                )
        ) {
            revert PaymasterConfigLengthInvalid();
        }

        uint48 validUntil = uint48(bytes6(_paymasterConfig[0:6]));
        uint48 validAfter = uint48(bytes6(_paymasterConfig[6:12]));
        address token = address(bytes20(_paymasterConfig[12:32]));
        uint128 postOpGas = uint128(bytes16(_paymasterConfig[32:48]));
        uint256 exchangeRate = uint256(bytes32(_paymasterConfig[48:80]));
        uint128 paymasterValidationGasLimit = uint128(bytes16(_paymasterConfig[80:96]));
        address treasury = address(bytes20(_paymasterConfig[96:116]));

        uint128 constantFee = 0;
        bytes calldata signature;

        if (_mode == ERC20_WITH_CONSTANT_FEE_MODE) {
            constantFee = uint128(bytes16(_paymasterConfig[116:132]));
            signature = _paymasterConfig[132:];
        } else {
            signature = _paymasterConfig[116:];
        }

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
            treasury: treasury,
            postOpGas: postOpGas,
            signature: signature,
            paymasterValidationGasLimit: paymasterValidationGasLimit,
            constantFee: constantFee
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
        address treasury = _cfg.treasury;
        uint128 constantFee = _cfg.constantFee;

        return abi.encode(
            ERC20PostOpContext({
                sender: _userOp.sender,
                token: _token,
                treasury: treasury,
                exchangeRate: _exchangeRate,
                postOpGas: _postOpGas,
                userOpHash: _userOpHash,
                maxFeePerGas: _userOp.maxFeePerGas,
                maxPriorityFeePerGas: _userOp.maxPriorityFeePerGas,
                preOpGasApproximation: uint256(0), // for v0.6 userOperations, we don't need this due to no penalty.
                executionGasLimit: uint256(0),
                constantFee: constantFee
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
        address treasury = _cfg.treasury;
        uint128 constantFee = _cfg.constantFee;
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
                treasury: treasury,
                exchangeRate: _exchangeRate,
                postOpGas: _postOpGas,
                userOpHash: _userOpHash,
                maxFeePerGas: uint256(0), // for v0.7 userOperations, the gasPrice is passed in the postOp.
                maxPriorityFeePerGas: uint256(0), // for v0.7 userOperations, the gasPrice is passed in the postOp.
                executionGasLimit: executionGasLimit,
                preOpGasApproximation: preOpGasApproximation,
                constantFee: constantFee
            })
        );
    }

    function _parsePostOpContext(
        bytes calldata _context
    )
        internal
        pure
        returns (address, address, address, uint256, uint128, bytes32, uint256, uint256, uint256, uint256, uint128)
    {
        ERC20PostOpContext memory ctx = abi.decode(_context, (ERC20PostOpContext));

        return (
            ctx.sender,
            ctx.token,
            ctx.treasury,
            ctx.exchangeRate,
            ctx.postOpGas,
            ctx.userOpHash,
            ctx.maxFeePerGas,
            ctx.maxPriorityFeePerGas,
            ctx.preOpGasApproximation,
            ctx.executionGasLimit,
            ctx.constantFee
        );
    }

    /**
     * @notice Gets the cost in amount of tokens.
     * @param _actualGasCost The gas consumed by the userOperation.
     * @param _postOpGas The gas overhead of transfering the ERC-20 when making the postOp payment.
     * @param _actualUserOpFeePerGas The actual gas cost of the userOperation.
     * @param _exchangeRate The token exchange rate - how many tokens one full ETH (1e18 wei) is worth.
     * @return uint256 The gasCost in token units.
     */
    function getCostInToken(
        uint256 _actualGasCost,
        uint256 _postOpGas,
        uint256 _actualUserOpFeePerGas,
        uint256 _exchangeRate
    )
        public
        pure
        returns (uint256)
    {
        return ((_actualGasCost + (_postOpGas * _actualUserOpFeePerGas)) * _exchangeRate) / 1e18;
    }
}
