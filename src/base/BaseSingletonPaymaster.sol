// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/* solhint-disable reason-string */
import {BasePaymaster} from "./BasePaymaster.sol";
import {IPaymasterV6} from "../interfaces/IPaymasterV6.sol";
import {PostOpMode} from "../interfaces/PostOpMode.sol";

import {UserOperation} from "@account-abstraction-v6/interfaces/IPaymaster.sol";
import {PackedUserOperation} from "@account-abstraction-v7/interfaces/PackedUserOperation.sol";
import {UserOperationLib as UserOperationLibV07} from "@account-abstraction-v7/core/UserOperationLib.sol";

import {Ownable} from "@openzeppelin-v5.0.0/contracts/access/Ownable.sol";

struct ERC20PaymasterData {
    /// @dev Timestamp until which the sponsorship is valid.
    uint48 validUntil;
    /// @dev Timestamp after which the sponsorship is valid.
    uint48 validAfter;
    /// @dev ERC20 token that the sender will pay with.
    address token;
    /// @dev The exchange rate of the ERC20 token during sponsorship.
    uint256 exchangeRate;
    /// @dev The paymaster signature.
    bytes signature;
}

abstract contract BaseSingletonPaymaster is Ownable, BasePaymaster {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CUSTOM ERRORS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The paymaster data length is invalid.
    error PaymasterAndDataLengthInvalid();

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
    // TODO: string instead of bytes?
    error PostOpTransferFromFailed(bytes msg);

    /// @dev When the paymaster fails to distribute funds to the smart account sender.
    // TODO: string instead of bytes?
    error FundDistributionFailed(bytes reason);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           EVENTS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Emitted when a user operation is sponsored by the paymaster.
    // TODO: move sponsoredWithErc20 above token and rename to paymasterMode???
    event UserOperationSponsored(
        bytes32 indexed userOpHash,
        address indexed user,
        address token,
        bool sponsoredWithErc20,
        uint256 tokenAmountPaid,
        uint256 tokenPrice,
        uint256 fundingAmount
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

    // TODO: move this shit to paymaster data
    uint256 internal constant POST_OP_GAS = 50_000;

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
    /// @dev Signers must be enabled separately after deployment.
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

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      INTERNAL HELPERS                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Parses the paymasterAndData field of the user operation and returns the paymaster mode and data.
    /// @notice _paymasterDataOffset is the start index of the data part of _paymasterAndData
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

    // TODO: natspec
    function _parseErc20Config(bytes calldata _paymasterConfig) internal pure returns (ERC20PaymasterData memory) {
        if (_paymasterConfig.length < 64) {
            revert PaymasterConfigLengthInvalid();
        }

        uint48 validUntil = uint48(bytes6(_paymasterConfig[0:6]));
        uint48 validAfter = uint48(bytes6(_paymasterConfig[6:12]));
        address token = address(bytes20(_paymasterConfig[12:32]));
        uint256 exchangeRate = uint256(bytes32(_paymasterConfig[32:64]));
        bytes calldata signature = _paymasterConfig[64:];

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
            signature: signature
        });

        return config;
    }

    // TODO: natspec
    function _parseVerifyingConfig(bytes calldata _paymasterConfig)
        internal
        pure
        returns (uint48, uint48, uint256, bytes calldata)
    {
        if (_paymasterConfig.length < 28) {
            revert PaymasterConfigLengthInvalid();
        }

        uint48 validUntil = uint48(bytes6(_paymasterConfig[0:6]));
        uint48 validAfter = uint48(bytes6(_paymasterConfig[6:12]));
        uint128 fundAmount = uint128(bytes16(_paymasterConfig[12:28]));
        bytes calldata signature = _paymasterConfig[28:];

        if (signature.length != 64 && signature.length != 65) {
            revert PaymasterSignatureLengthInvalid();
        }

        return (validUntil, validAfter, fundAmount, signature);
    }

    // TODO: natspec
    function _parsePostOpContext(bytes calldata _context)
        internal
        pure
        returns (address, address, uint256, bytes32, uint256, uint256)
    {
        address sender = address(bytes20(_context[0:20]));
        address token = address(bytes20(_context[20:40]));
        uint256 price = uint256(bytes32(_context[40:72]));
        bytes32 userOpHash = bytes32(_context[72:104]);
        uint256 maxFeePerGas = 0;
        uint256 maxPriorityFeePerGas = 0;

        if (_context.length == 168) {
            maxFeePerGas = uint256(bytes32(_context[104:136]));
            maxPriorityFeePerGas = uint256(bytes32(_context[136:168]));
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

    // TODO: natspec
    function _distributePaymasterDeposit(address payable _recipient, uint256 _fundAmount) internal {
        try entryPoint.withdrawTo(_recipient, _fundAmount) {
            // todo: remove??
            // emit FundsDistributed(_recipient, _fundAmount);
        } catch (bytes memory revertReason) {
            revert FundDistributionFailed(revertReason);
        }
    }
}
