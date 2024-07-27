// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test, console} from "forge-std/Test.sol";

import {BaseSingletonPaymaster} from "./base/BaseSingletonPaymaster.sol";
import {PostOpMode} from "./interfaces/PostOpMode.sol";

import {UserOperation} from "account-abstraction-v6/interfaces/IPaymaster.sol";
import {_packValidationData} from "account-abstraction-v6/core/Helpers.sol";

import {UserOperationLib} from "account-abstraction-v7/core/UserOperationLib.sol";
import {PackedUserOperation} from "account-abstraction-v7/interfaces/PackedUserOperation.sol";

import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol";
import {Math} from "openzeppelin-contracts/contracts/utils/math/Math.sol";

import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";

using UserOperationLib for PackedUserOperation;

contract SingletonPaymaster is BaseSingletonPaymaster {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CUSTOM ERRORS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The paymaster data mode is invalid. The mode should be 0 and 1.
    error PaymasterDataModeInvalid();

    /// @dev The paymaster data length is invalid for the selected mode.
    error PaymasterConfigLengthInvalid();

    /// @dev The token is invalid.
    error TokenAddressInvalid();

    /// @dev The token price is invalid.
    error PriceInvalid();

    /// @dev The signature length is invalid.
    error SignatureLengthInvalid();

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
    constructor(address _entryPoint, address _owner) BaseSingletonPaymaster(_entryPoint, _owner) {
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
    /*        ENTRYPOINT V0.7 ERC-4337 PAYMASTER OVERRIDES        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // @notice Skipped in verifying mode because postOp isn't called when context is empty.
    function _postOp(PostOpMode _mode, bytes calldata _context, uint256 _actualGasCost, uint256 _actualUserOpFeePerGas)
        internal
        override
    {
        (address sender, address token, uint256 price, bytes32 userOpHash,,) = _parseContext(_context);
        uint256 costInToken = ((_actualGasCost + (POST_OP_GAS * _actualUserOpFeePerGas)) * price) / 1e18;

        if (_mode != PostOpMode.postOpReverted) {
            SafeTransferLib.safeTransferFrom(token, sender, treasury, costInToken);
            emit UserOperationSponsored(userOpHash, sender, true, costInToken, price);
        }
    }

    function _validatePaymasterUserOp(PackedUserOperation calldata _userOp, bytes32 _userOpHash, uint256 /* maxCost */ )
        internal
        override
        returns (bytes memory, uint256)
    {
        (uint8 mode, bytes calldata paymasterConfig) = _parsePaymasterAndData(_userOp.paymasterAndData);

        if (mode == 0) {
            return _validateVerifyingMode(_userOp, paymasterConfig, _userOpHash);
        } else if (mode == 1) {
            return _validateERC20Mode(_userOp, paymasterConfig, _userOpHash);
        }

        // only valid modes are 1 and 0
        revert PaymasterDataModeInvalid();
    }

    function _validateVerifyingMode(
        PackedUserOperation calldata _userOp,
        bytes calldata _paymasterConfig,
        bytes32 _userOpHash
    ) internal returns (bytes memory, uint256) {
        (uint48 validUntil, uint48 validAfter, bytes calldata signature) = _parseVerifyingConfig(_paymasterConfig);

        bytes32 hash =
            MessageHashUtils.toEthSignedMessageHash(getHashV7(_userOp, validUntil, validAfter, address(0), 0));
        address verifyingSigner = ECDSA.recover(hash, signature);

        bool isSignatureValid = signers[verifyingSigner];
        uint256 validationData = _packValidationData(!isSignatureValid, validUntil, validAfter);

        emit UserOperationSponsored(_userOpHash, _userOp.getSender(), false, 0, 0);
        return ("", validationData);
    }

    function _validateERC20Mode(
        PackedUserOperation calldata _userOp,
        bytes calldata _paymasterConfig,
        bytes32 _userOpHash
    ) internal view returns (bytes memory, uint256) {
        (uint48 validUntil, uint48 validAfter, address token, uint256 price, bytes calldata signature) =
            _parseErc20Config(_paymasterConfig);

        bytes memory context = abi.encodePacked(_userOp.sender, token, price, _userOpHash);

        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(getHashV7(_userOp, validUntil, validAfter, token, price));
        address verifyingSigner = ECDSA.recover(hash, signature);

        bool isSignatureValid = signers[verifyingSigner];
        uint256 validationData = _packValidationData(!isSignatureValid, validUntil, validAfter);

        return (context, validationData);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*        ENTRYPOINT V0.6 ERC-4337 PAYMASTER OVERRIDES        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // @notice Skipped in verifying mode because postOp isn't called when context is empty.
    function _postOp(PostOpMode _mode, bytes calldata _context, uint256 _actualGasCost) internal override {
        (
            address sender,
            address token,
            uint256 price,
            bytes32 userOpHash,
            uint256 maxFeePerGas,
            uint256 maxPriorityFeePerGas
        ) = _parseContext(_context);

        uint256 actualUserOpFeePerGas;
        if (maxFeePerGas == maxPriorityFeePerGas) {
            // chains that only support legacy (pre eip-1559 transactions)
            actualUserOpFeePerGas = maxFeePerGas;
        } else {
            actualUserOpFeePerGas = Math.min(maxFeePerGas, maxPriorityFeePerGas + block.basefee);
        }

        uint256 costInToken = ((_actualGasCost + (POST_OP_GAS * actualUserOpFeePerGas)) * price) / 1e18;

        if (_mode != PostOpMode.postOpReverted) {
            SafeTransferLib.safeTransferFrom(token, sender, treasury, costInToken);
            emit UserOperationSponsored(userOpHash, sender, true, costInToken, price);
        }
    }

    function _validatePaymasterUserOp(UserOperation calldata _userOp, bytes32 _userOpHash, uint256 /* maxCost */ )
        internal
        override
        returns (bytes memory, uint256)
    {
        (uint8 mode, bytes calldata paymasterConfig) = _parsePaymasterAndData(_userOp.paymasterAndData);

        if (mode == 0) {
            return _validateVerifyingMode(_userOp, paymasterConfig, _userOpHash);
        } else if (mode == 1) {
            return _validateERC20Mode(_userOp, paymasterConfig, _userOpHash);
        }

        // only valid modes are 1 and 0
        revert PaymasterDataModeInvalid();
    }

    function _validateVerifyingMode(
        UserOperation calldata _userOp,
        bytes calldata _paymasterConfig,
        bytes32 _userOpHash
    ) internal returns (bytes memory, uint256) {
        (uint48 validUntil, uint48 validAfter, bytes calldata signature) = _parseVerifyingConfig(_paymasterConfig);
        bytes32 hash =
            MessageHashUtils.toEthSignedMessageHash(getHashV6(_userOp, validUntil, validAfter, address(0), 0));
        address verifyingSigner = ECDSA.recover(hash, signature);

        bool isSignatureValid = signers[verifyingSigner];
        uint256 validationData = _packValidationData(!isSignatureValid, validUntil, validAfter);

        emit UserOperationSponsored(_userOpHash, _userOp.sender, false, 0, 0);
        return ("", validationData);
    }

    function _validateERC20Mode(UserOperation calldata _userOp, bytes calldata _paymasterConfig, bytes32 _userOpHash)
        internal
        view
        returns (bytes memory, uint256)
    {
        (uint48 validUntil, uint48 validAfter, address token, uint256 price, bytes calldata signature) =
            _parseErc20Config(_paymasterConfig);

        bytes memory context = _createContext(_userOp, token, price, _userOpHash);

        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(getHashV6(_userOp, validUntil, validAfter, token, price));
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
    function getHashV6(
        UserOperation calldata _userOp,
        uint256 _validUntil,
        uint256 _validAfter,
        address _token,
        uint256 _price
    ) public view returns (bytes32) {
        bytes32 userOpHash = keccak256(
            abi.encode(
                _userOp.sender,
                _userOp.nonce,
                keccak256(_userOp.initCode),
                keccak256(_userOp.callData),
                _userOp.callGasLimit,
                _userOp.verificationGasLimit,
                _userOp.preVerificationGas,
                _userOp.maxFeePerGas,
                _userOp.maxPriorityFeePerGas
            )
        );

        return keccak256(abi.encode(userOpHash, block.chainid, address(this), _validUntil, _validAfter, _price, _token));
    }

    /// @notice Hashes the user operation data.
    /// @dev In verifying mode, _token and _price are 0.
    /// @param _userOp The user operation data.
    /// @param _validUntil The timestamp until which the user operation is valid.
    /// @param _validAfter The timestamp after which the user operation is valid.
    /// @param _price The maximum amount of tokens allowed for the user operation. 0 if no limit.
    function getHashV7(
        PackedUserOperation calldata _userOp,
        uint48 _validUntil,
        uint48 _validAfter,
        address _token,
        uint256 _price
    ) public view returns (bytes32) {
        address sender = _userOp.getSender();
        bytes32 userOpHash = keccak256(
            abi.encode(
                sender,
                _userOp.nonce,
                keccak256(_userOp.initCode),
                keccak256(_userOp.callData),
                _userOp.accountGasLimits,
                _userOp.preVerificationGas,
                _userOp.gasFees
            )
        );

        return keccak256(abi.encode(userOpHash, block.chainid, address(this), _validUntil, _validAfter, _price, _token));
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
        private
        pure
        returns (uint48, uint48, address, uint256, bytes calldata)
    {
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
            revert SignatureLengthInvalid();
        }

        return (validUntil, validAfter, token, price, signature);
    }

    function _parseVerifyingConfig(bytes calldata _paymasterConfig)
        private
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
            revert SignatureLengthInvalid();
        }

        return (validUntil, validAfter, signature);
    }

    function _parseContext(bytes calldata _context)
        private
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
