// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {SignatureCheckerExtended} from "../libraries/SignatureCheckerExtended.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

/**
 * @title SmartAccountWithERC7913
 * @dev A simple smart contract account that supports ERC-7913 signers alongside EOAs and ERC-1271
 * @notice This contract demonstrates how to integrate ERC-7913 signature verification
 * 
 * Features:
 * - Add/remove signers (EOA, ERC-1271, or ERC-7913 format)
 * - Execute transactions with valid signatures
 * - Multi-signer support
 * - Nonce-based replay protection
 * - ERC-1271 compatible
 */
contract SmartAccountWithERC7913 is IERC1271 {
    using SignatureCheckerExtended for bytes;

    /// @dev ERC-1271 magic value
    bytes4 private constant ERC1271_MAGIC_VALUE = 0x1626ba7e;

    /// @dev Owner of the account
    address public owner;
    
    /// @dev Mapping of authorized signers
    mapping(bytes32 => bool) public authorizedSigners;
    
    /// @dev Nonce for replay protection
    uint256 public nonce;

    /// @dev Events
    event SignerAdded(bytes signer);
    event SignerRemoved(bytes signer);
    event TransactionExecuted(address indexed to, uint256 value, bytes data);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /// @dev Errors
    error Unauthorized();
    error InvalidSigner();
    error ExecutionFailed();
    error InvalidSignature();

    /**
     * @dev Modifier to restrict access to owner only
     */
    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    /**
     * @dev Constructor sets the initial owner
     * @param _owner Initial owner address
     */
    constructor(address _owner) {
        owner = _owner;
        
        // Add owner as authorized signer (EOA format - 20 bytes)
        bytes memory ownerSigner = abi.encodePacked(_owner);
        bytes32 signerHash = keccak256(ownerSigner);
        authorizedSigners[signerHash] = true;
        
        emit SignerAdded(ownerSigner);
    }

    /**
     * @dev Allows contract to receive ETH
     */
    receive() external payable {}

    /**
     * @dev Adds a new authorized signer
     * @param signer The signer to add (20 bytes for EOA/ERC-1271, >20 for ERC-7913)
     */
    function addSigner(bytes calldata signer) external onlyOwner {
        if (!signer.isValidSignerFormat()) revert InvalidSigner();
        
        bytes32 signerHash = keccak256(signer);
        authorizedSigners[signerHash] = true;
        
        emit SignerAdded(signer);
    }

    /**
     * @dev Removes an authorized signer
     * @param signer The signer to remove
     */
    function removeSigner(bytes calldata signer) external onlyOwner {
        bytes32 signerHash = keccak256(signer);
        authorizedSigners[signerHash] = false;
        
        emit SignerRemoved(signer);
    }

    /**
     * @dev Checks if a signer is authorized
     * @param signer The signer to check
     * @return bool True if authorized
     */
    function isSigner(bytes calldata signer) external view returns (bool) {
        bytes32 signerHash = keccak256(signer);
        return authorizedSigners[signerHash];
    }

    /**
     * @dev Executes a transaction if signature is valid
     * @param to Destination address
     * @param value ETH value to send
     * @param data Transaction data
     * @param signer The signer authorizing this transaction
     * @param signature Signature over the transaction hash
     */
    function executeTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        bytes calldata signer,
        bytes calldata signature
    ) external returns (bytes memory) {
        // Build transaction hash with nonce for replay protection
        bytes32 txHash = getTransactionHash(to, value, data, nonce);
        
        // Verify signer is authorized
        bytes32 signerHash = keccak256(signer);
        if (!authorizedSigners[signerHash]) revert Unauthorized();
        
        // Verify signature using SignatureCheckerExtended
        if (!signer.isValidSignatureNow(txHash, signature)) {
            revert InvalidSignature();
        }
        
        // Increment nonce
        nonce++;
        
        // Execute transaction
        (bool success, bytes memory result) = to.call{value: value}(data);
        if (!success) revert ExecutionFailed();
        
        emit TransactionExecuted(to, value, data);
        
        return result;
    }

    /**
     * @dev Computes the hash of a transaction
     * @param to Destination address
     * @param value ETH value
     * @param data Transaction data
     * @param _nonce Current nonce
     * @return bytes32 Transaction hash
     */
    function getTransactionHash(
        address to,
        uint256 value,
        bytes calldata data,
        uint256 _nonce
    ) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19\x01", // EIP-191 version
                block.chainid,
                address(this),
                to,
                value,
                data,
                _nonce
            )
        );
    }

    /**
     * @dev ERC-1271 signature validation
     * @param hash Hash of the data to validate
     * @param signature Signature to validate
     * @return bytes4 Magic value if valid, 0xffffffff otherwise
     */
    function isValidSignature(
        bytes32 hash,
        bytes calldata signature
    ) external view override returns (bytes4) {
        // Signature format: signer || actual_signature
        // We need to extract the signer from the signature
        
        // For simplicity, we expect signature format:
        // [signerLength(2)][signer][signature]
        
        if (signature.length < 22) { // Minimum: 2 + 20 + 0
            return bytes4(0xffffffff);
        }
        
        uint16 signerLength = uint16(bytes2(signature[0:2]));
        
        if (signature.length < 2 + signerLength) {
            return bytes4(0xffffffff);
        }
        
        bytes calldata signer = signature[2:2 + signerLength];
        bytes calldata actualSignature = signature[2 + signerLength:];
        
        // Check if signer is authorized
        bytes32 signerHash = keccak256(signer);
        if (!authorizedSigners[signerHash]) {
            return bytes4(0xffffffff);
        }
        
        // Verify signature
        bool isValid = signer.isValidSignatureNow(hash, actualSignature);
        
        return isValid ? ERC1271_MAGIC_VALUE : bytes4(0xffffffff);
    }

    /**
     * @dev Transfers ownership of the account
     * @param newOwner New owner address
     */
    function transferOwnership(address newOwner) external onlyOwner {
        address oldOwner = owner;
        owner = newOwner;
        
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}