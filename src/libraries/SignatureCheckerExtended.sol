// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {IERC7913SignatureVerifier} from "../interfaces/IERC7913SignatureVerifier.sol";

/**
 * @title SignatureCheckerExtended
 * @dev Extension of OpenZeppelin's SignatureChecker to support ERC-7913 signature verifiers
 * @notice This library provides backward compatibility with EOAs and ERC-1271 while adding ERC-7913 support
 */
library SignatureCheckerExtended {
    /**
     * @dev Invalid signer format - must be at least 20 bytes
     */
    error InvalidSignerLength();

    /**
     * @dev Checks if a signature is valid for a given signer and hash
     * @param signer The signer in format: verifier_address (20 bytes) || key (variable)
     *               - If 20 bytes: treated as EOA or ERC-1271 contract address
     *               - If >20 bytes: first 20 bytes = verifier address, rest = key
     * @param hash The hash that was signed
     * @param signature The signature bytes
     * @return bool True if signature is valid, false otherwise
     *
     * Verification logic:
     * 1. If signer < 20 bytes: return false
     * 2. If signer == 20 bytes: use standard EOA/ERC-1271 verification
     * 3. If signer > 20 bytes: use ERC-7913 verifier
     */
    function isValidSignatureNow(
        bytes calldata signer,
        bytes32 hash,
        bytes memory signature
    ) internal view returns (bool) {
        // Case 1: Invalid length
        if (signer.length < 20) {
            return false;
        }
        
        // Case 2: Standard EOA or ERC-1271 (20 bytes)
        if (signer.length == 20) {
            address signerAddress = address(bytes20(signer));
            return SignatureChecker.isValidSignatureNow(
                signerAddress,
                hash,
                signature
            );
        }
        
        // Case 3: ERC-7913 verifier (>20 bytes)
        address verifier = address(bytes20(signer[0:20]));
        bytes calldata key = signer[20:];
        
        try IERC7913SignatureVerifier(verifier).verify(key, hash, signature) 
            returns (bytes4 magic) {
            return magic == IERC7913SignatureVerifier.verify.selector;
        } catch {
            return false;
        }
    }

    /**
     * @dev Encodes a verifier address and key into a signer bytes format
     * @param verifier The address of the verifier contract
     * @param key The public key bytes
     * @return signer The encoded signer (verifier || key)
     */
    function encodeSigner(
        address verifier,
        bytes memory key
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(verifier, key);
    }

    /**
     * @dev Decodes a signer into verifier address and key
     * @param signer The encoded signer bytes
     * @return verifier The verifier contract address
     * @return key The public key bytes
     */
    function decodeSigner(
        bytes calldata signer
    ) internal pure returns (address verifier, bytes calldata key) {
        if (signer.length < 20) {
            revert InvalidSignerLength();
        }
        
        verifier = address(bytes20(signer[0:20]));
        
        // Always assign key to avoid calldata pointer issues
        if (signer.length > 20) {
            key = signer[20:];
        } else {
            // Assign empty slice when length == 20
            key = signer[20:20];
        }
    }

    /**
     * @dev Validates that a signer has the correct format
     * @param signer The signer to validate
     * @return bool True if valid format
     */
    function isValidSignerFormat(bytes calldata signer) internal pure returns (bool) {
        return signer.length >= 20;
    }

    /**
     * @dev Gets the verifier address from a signer
     * @param signer The encoded signer
     * @return address The verifier address
     */
    function getVerifier(bytes calldata signer) internal pure returns (address) {
        if (signer.length < 20) {
            revert InvalidSignerLength();
        }
        return address(bytes20(signer[0:20]));
    }

    /**
     * @dev Checks if a signer is ERC-7913 format (>20 bytes)
     * @param signer The signer to check
     * @return bool True if ERC-7913 format
     */
    function isERC7913Signer(bytes calldata signer) internal pure returns (bool) {
        return signer.length > 20;
    }
}