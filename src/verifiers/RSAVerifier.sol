// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC7913SignatureVerifier} from "../interfaces/IERC7913SignatureVerifier.sol";

/**
 * @title RSAVerifier
 * @dev ERC-7913 compliant verifier for RSA signatures with PKCS#1 v1.5 padding
 * @notice This is a simplified RSA verifier for demonstration purposes
 *         Production use requires more robust implementation and gas optimization
 * 
 * Key Format: modulusLength (32 bytes) || modulus || exponent
 * Signature Format: RSA signature bytes (same length as modulus)
 * 
 * WARNING: RSA verification in Solidity is gas-intensive. Use with caution.
 */
contract RSAVerifier is IERC7913SignatureVerifier {
    /// @dev Minimum key length (2048 bits = 256 bytes)
    uint256 private constant MIN_KEY_LENGTH = 256;
    
    /// @dev Maximum key length (4096 bits = 512 bytes) 
    uint256 private constant MAX_KEY_LENGTH = 512;
    
    /// @dev Typical exponent is 65537 (0x010001)
    uint256 private constant COMMON_EXPONENT = 65537;

    error InvalidKeyFormat();
    error InvalidSignatureLength();
    error KeyTooShort();
    error KeyTooLong();
    error InvalidPadding();

    /**
     * @inheritdoc IERC7913SignatureVerifier
     * @dev Verifies an RSA signature with PKCS#1 v1.5 padding
     * @param key RSA public key: modulusLength (32) || modulus (N bytes) || exponent (32)
     * @param hash The message hash (will be re-padded with PKCS#1 v1.5)
     * @param signature The RSA signature
     */
    function verify(
        bytes calldata key,
        bytes32 hash,
        bytes calldata signature
    ) external view override returns (bytes4) {
        // Parse key format: [modulusLength(32)][modulus][exponent(32)]
        if (key.length < 65) { // At least 32 + 1 + 32
            revert InvalidKeyFormat();
        }

        // Extract modulus length
        uint256 modulusLength = uint256(bytes32(key[0:32]));
        
        // Validate modulus length
        if (modulusLength < MIN_KEY_LENGTH) revert KeyTooShort();
        if (modulusLength > MAX_KEY_LENGTH) revert KeyTooLong();
        
        // Validate total key length
        if (key.length != 32 + modulusLength + 32) {
            revert InvalidKeyFormat();
        }
        
        // Extract components
        bytes memory modulus = key[32:32 + modulusLength];
        uint256 exponent = uint256(bytes32(key[32 + modulusLength:]));
        
        // Signature must be same length as modulus
        if (signature.length != modulusLength) {
            revert InvalidSignatureLength();
        }

        // Verify signature
        bool isValid = _verifyRSA(hash, signature, modulus, exponent);
        
        return isValid 
            ? IERC7913SignatureVerifier.verify.selector 
            : bytes4(0xffffffff);
    }

    /**
     * @dev Verifies RSA signature using modular exponentiation
     * @param hash The message hash
     * @param signature The RSA signature
     * @param modulus The RSA modulus (N)
     * @param exponent The RSA public exponent (e)
     * @return bool True if signature is valid
     */
    function _verifyRSA(
        bytes32 hash,
        bytes calldata signature,
        bytes memory modulus,
        uint256 exponent
    ) private view returns (bool) {
        // Convert signature to uint
        uint256 sig = bytesToUint(signature);
        uint256 mod = bytesToUint(modulus);
        
        // Perform modular exponentiation: sig^e mod N
        uint256 result = modExp(sig, exponent, mod);
        
        // Convert result back to bytes
        bytes memory decrypted = uintToBytes(result, modulus.length);
        
        // Verify PKCS#1 v1.5 padding
        return _verifyPKCS1v15Padding(decrypted, hash);
    }

    /**
     * @dev Verifies PKCS#1 v1.5 padding format
     * @param decrypted The decrypted signature (should contain padded hash)
     * @param hash The expected hash
     * @return bool True if padding is valid and hash matches
     * 
     * PKCS#1 v1.5 format: 0x00 || 0x01 || PS || 0x00 || DigestInfo
     * Where PS is padding of 0xff bytes
     * DigestInfo contains the hash algorithm OID and the hash value
     */
    function _verifyPKCS1v15Padding(
        bytes memory decrypted,
        bytes32 hash
    ) private pure returns (bool) {
        uint256 len = decrypted.length;
        
        // Check minimum length (at least 11 bytes of padding + hash info)
        if (len < 11 + 32) return false;
        
        // Check header: 0x00 0x01
        if (decrypted[0] != 0x00 || decrypted[1] != 0x01) return false;
        
        // Find the 0x00 separator after padding
        uint256 separatorIndex = 2;
        while (separatorIndex < len && decrypted[separatorIndex] == 0xff) {
            separatorIndex++;
        }
        
        // Must have at least 8 bytes of 0xff padding
        if (separatorIndex < 10) return false;
        
        // Check separator
        if (decrypted[separatorIndex] != 0x00) return false;
        
        // The rest should be DigestInfo + hash
        // For SHA-256: DigestInfo is 19 bytes + 32 bytes hash
        uint256 hashStart = len - 32;
        
        // Extract and compare hash
        bytes32 extractedHash;
        assembly {
            extractedHash := mload(add(add(decrypted, 32), hashStart))
        }
        
        return extractedHash == hash;
    }

    /**
     * @dev Modular exponentiation: (base^exponent) % modulus
     * @param base The base
     * @param exponent The exponent
     * @param modulus The modulus
     * @return result The result of (base^exponent) % modulus
     */
    function modExp(
        uint256 base,
        uint256 exponent,
        uint256 modulus
    ) private view returns (uint256 result) {
        // Use precompiled contract at address 0x05
        bytes memory input = abi.encodePacked(
            uint256(32), // length of base
            uint256(32), // length of exponent
            uint256(32), // length of modulus
            base,
            exponent,
            modulus
        );
        
        assembly {
            let success := staticcall(
                gas(),
                0x05,
                add(input, 0x20),
                mload(input),
                mload(0x40),
                0x20
            )
            result := mload(mload(0x40))
        }
    }

    /**
     * @dev Converts bytes to uint256
     */
    function bytesToUint(bytes memory b) private pure returns (uint256) {
        uint256 number = 0;
        for (uint256 i = 0; i < b.length; i++) {
            number = number * 256 + uint8(b[i]);
        }
        return number;
    }

    /**
     * @dev Converts uint256 to bytes with specified length
     */
    function uintToBytes(
        uint256 x,
        uint256 length
    ) private pure returns (bytes memory) {
        bytes memory b = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            b[length - 1 - i] = bytes1(uint8(x % 256));
            x /= 256;
        }
        return b;
    }
}