// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {BasePaymaster} from "account-abstraction-v7/core/BasePaymaster.sol";
import {_packValidationData} from "account-abstraction-v7/core/Helpers.sol";
import {UserOperationLib} from "account-abstraction-v7/core/UserOperationLib.sol";
import {IEntryPoint} from "account-abstraction-v7/interfaces/IEntryPoint.sol";
import {IPaymaster} from "account-abstraction-v7/interfaces/IPaymaster.sol";
import {PackedUserOperation} from "account-abstraction-v7/interfaces/PackedUserOperation.sol";

import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol";
import {Math} from "openzeppelin-contracts/contracts/utils/math/Math.sol";

import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";

using UserOperationLib for PackedUserOperation;
using ECDSA for bytes32;
using MessageHashUtils for bytes32;

contract SingletonPaymaster is BasePaymaster {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CUSTOM ERRORS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The paymaster data mode is invalid. The mode should be 0 and 1.
    error PaymasterDataModeInvalid();

    /// @dev The paymaster data length is invalid for the selected mode.
    error PaymasterConfigLengthInvalid();

    /// @dev The paymaster was called with a invalid token.
    error NullTokenAddress();

    /// @dev The paymaster was called with a invalid price.
    error InvalidPrice();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  CONSTANTS AND IMMUTABLES                  */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    uint256 private constant POST_OP_GAS = 50_000;
    uint256 private constant PAYMASTER_CONFIG_OFFSET = PAYMASTER_DATA_OFFSET + 1;

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
    constructor(IEntryPoint _entryPoint, address _owner) BasePaymaster(_entryPoint) {
        _transferOwnership(_owner);
        treasury = _owner;
        signers[_owner] = true;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      ADMIN FUNCTIONS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function removeSigner(address _signer) public onlyOwner {
        signers[_signer] = false;
    }

    function addSigner(address _signer) public onlyOwner {
        signers[_signer] = true;
    }

    function setTreasury(address _treasury) public onlyOwner {
        treasury = _treasury;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                ERC-4337 PAYMASTER FUNCTIONS                */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // @notice Skipped in verifying mode because postOp isn't called when context is empty.
    function _postOp(PostOpMode, bytes calldata context, uint256 actualGasCost, uint256 actualUserOpFeePerGas)
        internal
        override
    {
        (address sender, address token, uint256 price) = abi.decode(context, (address, address, uint256));
        uint256 costInToken = ((actualGasCost + (POST_OP_GAS * actualUserOpFeePerGas)) * price) / 1e18;

        SafeTransferLib.safeTransferFrom(token, sender, treasury, costInToken);
    }

    function _validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32, /* userOpHash */
        uint256 /* maxCost */
    ) internal virtual override returns (bytes memory, uint256) {
        (uint8 mode, bytes calldata paymasterConfig) = _parsePaymasterAndData(userOp.paymasterAndData);

        if (mode == 0) {
            return _validateVerifyingMode(userOp, paymasterConfig);
        } else if (mode == 1) {
            return _validateERC20Mode(userOp, paymasterConfig);
        }

        // only valid modes are 1 and 0
        revert PaymasterDataModeInvalid();
    }

    function _validateVerifyingMode(PackedUserOperation calldata userOp, bytes calldata paymasterConfig)
        internal
        view
        returns (bytes memory, uint256)
    {
        if (paymasterConfig.length < 12) {
            revert PaymasterConfigLengthInvalid();
        }

        uint256 cursor = 0;
        uint48 validUntil = uint48(bytes6(paymasterConfig[cursor:cursor += 6]));
        uint48 validAfter = uint48(bytes6(paymasterConfig[cursor:cursor += 6]));
        bytes memory signature = paymasterConfig[cursor:];

        require(signature.length == 64 || signature.length == 65, "VerifyingPaymaster: invalid signature length");
        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(getHash(userOp, validUntil, validAfter, address(0), 0));
        address verifyingSigner = ECDSA.recover(hash, signature);

        bool isSignatureValid = signers[verifyingSigner];
        uint256 validationData = _packValidationData(!isSignatureValid, validUntil, validAfter);

        return ("", validationData);
    }

    function _validateERC20Mode(PackedUserOperation calldata userOp, bytes calldata paymasterConfig)
        internal
        view
        returns (bytes memory, uint256)
    {
        if (paymasterConfig.length < 64) {
            revert PaymasterConfigLengthInvalid();
        }

        uint256 cursor = 0;
        uint48 validUntil = uint48(bytes6(paymasterConfig[cursor:cursor += 6]));
        uint48 validAfter = uint48(bytes6(paymasterConfig[cursor:cursor += 6]));
        address token = address(bytes20(paymasterConfig[cursor:cursor += 20]));
        uint256 price = uint256(bytes32(paymasterConfig[cursor:cursor += 32]));
        bytes memory signature = paymasterConfig[cursor:];

        if (token == address(0)) {
            revert NullTokenAddress();
        }

        if (price == 0) {
            revert InvalidPrice();
        }

        bytes memory context = abi.encode(userOp.sender, token, price);

        require(signature.length == 64 || signature.length == 65, "VerifyingPaymaster: invalid signature length");
        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(getHash(userOp, validUntil, validAfter, token, price));
        address verifyingSigner = ECDSA.recover(hash, signature);

        bool isSignatureValid = signers[verifyingSigner];
        uint256 validationData = _packValidationData(!isSignatureValid, validUntil, validAfter);

        return (context, validationData);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PUBLIC HELPERS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Hashes the user operation data.
    /// @dev In verifying mode, _token and _price are 0.
    /// @param _userOp The user operation data.
    /// @param _validUntil The timestamp until which the user operation is valid.
    /// @param _validAfter The timestamp after which the user operation is valid.
    /// @param _price The maximum amount of tokens allowed for the user operation. 0 if no limit.
    function getHash(
        PackedUserOperation calldata _userOp,
        uint48 _validUntil,
        uint48 _validAfter,
        address _token,
        uint256 _price
    ) public view returns (bytes32) {
        address sender = _userOp.getSender();
        return keccak256(
            abi.encode(
                sender,
                _userOp.nonce,
                keccak256(_userOp.initCode),
                keccak256(_userOp.callData),
                _userOp.accountGasLimits,
                _userOp.preVerificationGas,
                _userOp.gasFees,
                block.chainid,
                address(this),
                _validUntil,
                _validAfter,
                _price,
                _token
            )
        );
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      INTERNAL HELPERS                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Parses the paymasterAndData field of the user operation and returns the paymaster mode and data.
    /// @param _paymasterAndData The paymasterAndData field of the user operation.
    /// @return mode The paymaster mode.
    /// @return paymasterConfig The paymaster configuration data.
    function _parsePaymasterAndData(bytes calldata _paymasterAndData) internal pure returns (uint8, bytes calldata) {
        uint8 mode = uint8(bytes1(_paymasterAndData[PAYMASTER_DATA_OFFSET:PAYMASTER_DATA_OFFSET + 1]));
        bytes calldata paymasterConfig = _paymasterAndData[PAYMASTER_DATA_OFFSET + 1:];

        return (mode, paymasterConfig);
    }
}
