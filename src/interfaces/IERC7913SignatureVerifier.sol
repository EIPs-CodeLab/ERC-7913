// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IERC7913SignatureVerifier
 * @dev Interface for signature verification contracts as defined in EIP-7913
 * @notice Verifiers implement this interface to validate signatures for keys without Ethereum addresses
 */
interface IERC7913SignatureVerifier {
    /**
     * @dev Verifies `signature` as a valid signature of `hash` by `key`.
     *
     * @param key The public key in bytes format (format depends on the cryptographic scheme)
     * @param hash The hash of the message that was signed (typically EIP-191 or EIP-712)
     * @param signature The signature to verify
     *
     * @return bytes4 Returns 0x024ad318 (this function's selector) if signature is valid
     *                Returns 0xffffffff or reverts if signature is invalid
     *                Should revert if key is empty
     *
     * Requirements:
     * - MUST return 0x024ad318 if the signature is valid
     * - SHOULD return 0xffffffff or revert if signature is invalid
     * - SHOULD revert if key is empty
     * - SHOULD be a view/pure function (stateless)
     */

    function verify(
        bytes calldata key,
        bytes32 hash, 
        bytes calldata signature
    )external view returns (bytes4);
}

