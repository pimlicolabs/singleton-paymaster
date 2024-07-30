// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

/* solhint-disable reason-string */
import {BasePaymaster} from "./BasePaymaster.sol";
import {IPaymasterV6} from "../interfaces/IPaymasterV6.sol";
import {PostOpMode} from "../interfaces/PostOpMode.sol";

import {UserOperation} from "@account-abstraction-v6/interfaces/IPaymaster.sol";
import {PackedUserOperation} from "@account-abstraction-v7/interfaces/PackedUserOperation.sol";
import {UserOperationLib as UserOperationLibV07} from "@account-abstraction-v7/core/UserOperationLib.sol";

import {Ownable} from "@openzeppelin-v5.0.0/contracts/access/Ownable.sol";

struct ERC20Config {
    uint48 validUntil;
    uint48 validAfter;
    address token;
    uint256 exchangeRate;
    bytes signature;
}

abstract contract BaseSingletonPaymaster is Ownable {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CUSTOM ERRORS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The paymaster data length is invalid.
    error PaymasterDataLengthInvalid();

    /// @dev The paymaster data mode is invalid. The mode should be 0 and 1.
    error PaymasterModeInvalid();

    /// @dev The paymaster data length is invalid for the selected mode.
    error PaymasterConfigLengthInvalid();

    /// @dev The paymaster signature length is invalid.
    error PaymasterSignatureLengthInvalid();

    /// @dev The token is invalid.
    error TokenAddressInvalid();

    /// @dev The token exchange rate is invalid.
    error ExchangeRateInvalid();

    /// @dev When payment failed due to the TransferFrom in the PostOp failing.
    error PostOpTransferFromFailed(bytes reason);

    /// @dev When the paymaster fails to distribute funds to the smart account sender.
    error FundDistributionFailed(bytes reason);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           EVENTS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Emitted when a user operation is sponsored by the paymaster.
    event UserOperationSponsored(
        bytes32 indexed userOpHash,
        address indexed user,
        address token,
        bool sponsoredWithErc20,
        uint256 tokenAmountPaid,
        uint256 tokenPrice
    );

    /// @dev Emitted when a new treasury is set.
    event TreasuryUpdated(address oldTreasury, address newTreasury);

    /// @dev Emitted when a signer is added.
    event SignerAdded(address signer);

    /// @dev Emitted when a signer is removed.
    event SignerRemoved(address signer);

    /// @dev When the user receives funds from the paymaster.
    event FundsDistributed(address indexed receiver, uint256 fundingAmount);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  CONSTANTS AND IMMUTABLES                  */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    uint256 internal constant POST_OP_GAS = 50_000;
    uint256 internal constant PAYMASTER_VALIDATION_GAS_OFFSET = UserOperationLibV07.PAYMASTER_VALIDATION_GAS_OFFSET;
    uint256 internal constant PAYMASTER_POSTOP_GAS_OFFSET = UserOperationLibV07.PAYMASTER_POSTOP_GAS_OFFSET;
    uint256 internal constant PAYMASTER_DATA_OFFSET = UserOperationLibV07.PAYMASTER_DATA_OFFSET;
    // @notice Offset of 17 bytes from PAYMASTER_DATA_OFFSET after extracting mode + fundAmount
    uint256 internal constant PAYMASTER_CONFIG_OFFSET = PAYMASTER_DATA_OFFSET + 1 + 16;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          STORAGE                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Mapping of valid signers.
    mapping(address account => bool isValidSigner) public signers;

    /// @dev Address where all ERC20 tokens will be sent to.
    address public treasury;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        CONSTRUCTOR                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Initializes the SingletonPaymaster contract with the given parameters.
    /// @param _owner The address that will be set as the owner of the contract.
    constructor(address _owner) {
        treasury = _owner;
        signers[_owner] = true;
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

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      INTERNAL HELPERS                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Parses the paymasterAndData field of the user operation and returns the paymaster mode and data.
    /// @param _paymasterAndData The paymasterAndData field of the user operation.
    /// @return mode The paymaster mode.
    /// @return paymasterConfig The paymaster configuration data.
    function _parsePaymasterAndData(bytes calldata _paymasterAndData)
        internal
        pure
        returns (uint8, uint256, bytes calldata)
    {
        if (_paymasterAndData.length < PAYMASTER_CONFIG_OFFSET) {
            revert PaymasterDataLengthInvalid();
        }

        uint256 cursor = PAYMASTER_DATA_OFFSET;
        uint8 mode = uint8(bytes1(_paymasterAndData[cursor:cursor += 1]));
        uint128 fundAmount = uint128(bytes16(_paymasterAndData[cursor:cursor += 16]));
        bytes calldata paymasterConfig = _paymasterAndData[cursor:];

        return (mode, uint256(fundAmount), paymasterConfig);
    }

    function _parseErc20Config(bytes calldata _paymasterConfig) internal pure returns (ERC20Config memory) {
        if (_paymasterConfig.length < 64) {
            revert PaymasterConfigLengthInvalid();
        }

        uint256 cursor = 0;
        uint48 validUntil = uint48(bytes6(_paymasterConfig[cursor:cursor += 6]));
        uint48 validAfter = uint48(bytes6(_paymasterConfig[cursor:cursor += 6]));
        address token = address(bytes20(_paymasterConfig[cursor:cursor += 20]));
        uint256 exchangeRate = uint256(bytes32(_paymasterConfig[cursor:cursor += 32]));
        bytes calldata signature = _paymasterConfig[cursor:];

        if (token == address(0)) {
            revert TokenAddressInvalid();
        }

        if (exchangeRate == 0) {
            revert ExchangeRateInvalid();
        }

        if (signature.length != 64 && signature.length != 65) {
            revert PaymasterSignatureLengthInvalid();
        }

        ERC20Config memory config = ERC20Config({
            validUntil: validUntil,
            validAfter: validAfter,
            token: token,
            exchangeRate: exchangeRate,
            signature: signature
        });

        return config;
    }

    function _parseVerifyingConfig(bytes calldata _paymasterConfig)
        internal
        pure
        returns (uint48, uint48, bytes calldata)
    {
        if (_paymasterConfig.length < 12) {
            revert PaymasterConfigLengthInvalid();
        }

        uint256 cursor = 0;
        uint48 validUntil = uint48(bytes6(_paymasterConfig[cursor:cursor += 6]));
        uint48 validAfter = uint48(bytes6(_paymasterConfig[cursor:cursor += 6]));
        bytes calldata signature = _paymasterConfig[cursor:];

        if (signature.length != 64 && signature.length != 65) {
            revert PaymasterSignatureLengthInvalid();
        }

        return (validUntil, validAfter, signature);
    }

    function _parseContext(bytes calldata _context)
        internal
        pure
        returns (address, address, uint256, bytes32, uint256, uint256)
    {
        uint256 cursor = 0;
        address sender = address(bytes20(_context[cursor:cursor += 20]));
        address token = address(bytes20(_context[cursor:cursor += 20]));
        uint256 price = uint256(bytes32(_context[cursor:cursor += 32]));
        bytes32 userOpHash = bytes32(_context[cursor:cursor += 32]);
        uint256 maxFeePerGas = 0;
        uint256 maxPriorityFeePerGas = 0;

        if (_context.length == 168) {
            maxFeePerGas = uint256(bytes32(_context[cursor:cursor += 32]));
            maxPriorityFeePerGas = uint256(bytes32(_context[cursor:cursor += 32]));
        }

        return (sender, token, price, userOpHash, maxFeePerGas, maxPriorityFeePerGas);
    }

    // @dev V6 Helper to bypass stack too deep issue.
    function _createContext(UserOperation calldata userOp, address token, uint256 price, bytes32 userOpHash)
        internal
        pure
        returns (bytes memory)
    {
        return
            abi.encodePacked(userOp.sender, token, price, userOpHash, userOp.maxFeePerGas, userOp.maxPriorityFeePerGas);
    }

    // @dev V7 Helper to bypass stack too deep issue.
    function _createContext(PackedUserOperation calldata userOp, address token, uint256 price, bytes32 userOpHash)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(userOp.sender, token, price, userOpHash, uint256(0), uint256(0));
    }
}
