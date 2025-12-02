// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IERC7913SignatureVerifier
 * @dev Interface for signature verification contracts as defined in EIP-7913
 * @notice Verifiers implement this interface to validate signatures for keys without Ethereum addresses
 */
interface IERC7913SignatureVerifier {

    function verify(
        bytes calldata key,
        bytes32 hash, 
        bytes calldata signature
    )external view returns (bytes4);
}
