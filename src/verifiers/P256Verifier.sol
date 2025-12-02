// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC7913SignatureVerifier} from "../interfaces/IERC7913SignatureVerifier.sol";

/**
 * @title P256Verifier
 * @dev ERC-7913 compliant verifier for P256 (secp256r1) signatures
 * @notice This verifier uses RIP-7212 precompile at address 0x100 if available,
 *         or falls back to a library implementation
 * 
 * Key Format: 64 bytes (x: 32 bytes || y: 32 bytes)
 * Signature Format: 64 bytes (r: 32 bytes || s: 32 bytes)
 */
contract P256Verifier is IERC7913SignatureVerifier {
    /// @dev RIP-7212 precompile address for P256 verification
    address private constant P256_PRECOMPILE = address(0x100);
    
    /// @dev Expected key length (64 bytes: 32 for x, 32 for y)
    uint256 private constant KEY_LENGTH = 64;
    
    /// @dev Expected signature length (64 bytes: 32 for r, 32 for s)
    uint256 private constant SIGNATURE_LENGTH = 64;

    /**
     * @dev Error thrown when key is empty or invalid length
     */
    error InvalidKeyLength();
    
    /**
     * @dev Error thrown when signature has invalid length
     */
    error InvalidSignatureLength();

    /**
     * @inheritdoc IERC7913SignatureVerifier
     * @dev Verifies a P256 signature
     * @param key The P256 public key (64 bytes: x || y)
     * @param hash The message hash (32 bytes)
     * @param signature The P256 signature (64 bytes: r || s)
     */
    function verify(
        bytes calldata key,
        bytes32 hash,
        bytes calldata signature
    ) external view override returns (bytes4) {
        // Validate key length
        if (key.length != KEY_LENGTH) {
            revert InvalidKeyLength();
        }
        
        // Validate signature length
        if (signature.length != SIGNATURE_LENGTH) {
            revert InvalidSignatureLength();
        }

        // Extract public key coordinates
        bytes32 x = bytes32(key[0:32]);
        bytes32 y = bytes32(key[32:64]);
        
        // Extract signature values
        bytes32 r = bytes32(signature[0:32]);
        bytes32 s = bytes32(signature[32:64]);

        // Verify using precompile or library
        bool isValid = _verifyP256Signature(hash, r, s, x, y);
        
        if (isValid) {
            return IERC7913SignatureVerifier.verify.selector;
        } else {
            return 0xffffffff;
        }
    }

    /**
     * @dev Internal function to verify P256 signature using precompile
     * @param hash Message hash
     * @param r Signature r value
     * @param s Signature s value
     * @param x Public key x coordinate
     * @param y Public key y coordinate
     * @return bool True if signature is valid
     */
    function _verifyP256Signature(
        bytes32 hash,
        bytes32 r,
        bytes32 s,
        bytes32 x,
        bytes32 y
    ) private view returns (bool) {
        // Check if RIP-7212 precompile exists
        if (_isPrecompileAvailable()) {
            return _verifyWithPrecompile(hash, r, s, x, y);
        } else {
            // Fallback to library implementation (you would need to add this)
            // For now, we'll revert if precompile not available
            revert("P256 precompile not available");
        }
    }

    /**
     * @dev Verifies signature using RIP-7212 precompile
     * @param hash Message hash
     * @param r Signature r value
     * @param s Signature s value  
     * @param x Public key x coordinate
     * @param y Public key y coordinate
     * @return bool True if valid
     */
    function _verifyWithPrecompile(
        bytes32 hash,
        bytes32 r,
        bytes32 s,
        bytes32 x,
        bytes32 y
    ) private view returns (bool) {
        // Prepare input for precompile: hash || r || s || x || y
        bytes memory input = abi.encodePacked(hash, r, s, x, y);
        
        // Call precompile
        (bool success, bytes memory result) = P256_PRECOMPILE.staticcall(input);
        
        // Check if call succeeded and returned true (1)
        if (!success || result.length != 32) {
            return false;
        }
        
        return abi.decode(result, (uint256)) == 1;
    }

    /**
     * @dev Checks if P256 precompile is available
     * @return bool True if precompile exists
     */
    function _isPrecompileAvailable() private view returns (bool) {
        // Check if code exists at precompile address
        uint256 size;
        assembly {
            size := extcodesize(P256_PRECOMPILE)
        }
        return size > 0;
    }
}