// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

/* solhint-disable reason-string */
import {BasePaymaster} from "./BasePaymaster.sol";
import {IPaymasterV6} from "../interfaces/IPaymasterV6.sol";
import {PostOpMode} from "../interfaces/PostOpMode.sol";

import {UserOperation} from "account-abstraction-v6/interfaces/IPaymaster.sol";
import {PackedUserOperation} from "account-abstraction-v7/interfaces/PackedUserOperation.sol";

// TODO: delete this import
import {Test, console} from "forge-std/Test.sol";

abstract contract BaseSingletonPaymaster is BasePaymaster {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CUSTOM ERRORS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The paymaster data mode is invalid. The mode should be 0 and 1.
    error PaymasterModeInvalid();

    /// @dev The paymaster data length is invalid for the selected mode.
    error PaymasterConfigLengthInvalid();

    /// @dev The paymaster signature length is invalid.
    error PaymasterSignatureLengthInvalid();

    /// @dev The token is invalid.
    error TokenAddressInvalid();

    /// @dev The token price is invalid.
    error PriceInvalid();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           EVENTS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Emitted when a user operation is sponsored by the paymaster.
    event UserOperationSponsored(
        bytes32 indexed userOpHash,
        address indexed user,
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

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  CONSTANTS AND IMMUTABLES                  */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    uint256 internal constant POST_OP_GAS = 50_000;
    uint256 internal constant PAYMASTER_CONFIG_OFFSET = PAYMASTER_DATA_OFFSET + 1;

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
    /// @param _entryPoint The ERC-4337 EntryPoint contract.
    /// @param _owner The address that will be set as the owner of the contract.
    constructor(address _entryPoint, address _owner) BasePaymaster(_entryPoint, _owner) {
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
    function _parsePaymasterAndData(bytes calldata _paymasterAndData) internal pure returns (uint8, bytes calldata) {
        if (_paymasterAndData.length < PAYMASTER_CONFIG_OFFSET) {
            return (0, msg.data[0:0]);
        }

        uint8 mode = uint8(bytes1(_paymasterAndData[PAYMASTER_DATA_OFFSET:PAYMASTER_DATA_OFFSET + 1]));
        bytes calldata paymasterConfig = _paymasterAndData[PAYMASTER_DATA_OFFSET + 1:];

        return (mode, paymasterConfig);
    }

    function _parseErc20Config(bytes calldata _paymasterConfig)
        internal
        pure
        returns (uint48, uint48, address, uint256, bytes calldata)
    {
        console.log("_parseErc20Config");
        if (_paymasterConfig.length < 64) {
            revert PaymasterConfigLengthInvalid();
        }

        uint256 cursor = 0;
        uint48 validUntil = uint48(bytes6(_paymasterConfig[cursor:cursor += 6]));
        uint48 validAfter = uint48(bytes6(_paymasterConfig[cursor:cursor += 6]));
        address token = address(bytes20(_paymasterConfig[cursor:cursor += 20]));
        uint256 price = uint256(bytes32(_paymasterConfig[cursor:cursor += 32]));
        bytes calldata signature = _paymasterConfig[cursor:];

        if (token == address(0)) {
            revert TokenAddressInvalid();
        }

        if (price == 0) {
            revert PriceInvalid();
        }

        if (signature.length != 64 && signature.length != 65) {
            revert PaymasterSignatureLengthInvalid();
        }

        return (validUntil, validAfter, token, price, signature);
    }

    function _parseVerifyingConfig(bytes calldata _paymasterConfig)
        internal
        pure
        returns (uint48, uint48, bytes calldata)
    {
        console.log("_parseVerifyingConfig");
        console.log("_paymasterConfig.length: ", _paymasterConfig.length);
        console.logBytes(_paymasterConfig);
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
        uint256 maxFeePerGas = uint256(bytes32(_context[cursor:cursor += 32]));
        uint256 maxPriorityFeePerGas = uint256(bytes32(_context[cursor:cursor += 32]));

        return (sender, token, price, userOpHash, maxFeePerGas, maxPriorityFeePerGas);
    }

    // @dev Helper to bypass stack too deep issue.
    function _createContext(UserOperation calldata userOp, address token, uint256 price, bytes32 userOpHash)
        internal
        pure
        returns (bytes memory)
    {
        return
            abi.encodePacked(userOp.sender, token, price, userOpHash, userOp.maxFeePerGas, userOp.maxPriorityFeePerGas);
    }
}
