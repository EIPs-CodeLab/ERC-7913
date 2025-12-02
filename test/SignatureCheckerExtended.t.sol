// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {SignatureCheckerExtended} from "../src/libraries/SignatureCheckerExtended.sol";
import {IERC7913SignatureVerifier} from "../src/interfaces/IERC7913SignatureVerifier.sol";

contract MockVerifier is IERC7913SignatureVerifier {
    bool public shouldSucceed;
    
    constructor(bool _shouldSucceed) {
        shouldSucceed = _shouldSucceed;
    }
    
    function verify(
        bytes calldata,
        bytes32,
        bytes calldata
    ) external view override returns (bytes4) {
        return shouldSucceed 
            ? IERC7913SignatureVerifier.verify.selector 
            : bytes4(0xffffffff);
    }
}

contract SignatureCheckerExtendedTest is Test {
    address private testAddress;
    uint256 private testPrivateKey;
    
    MockVerifier private validVerifier;
    MockVerifier private invalidVerifier;

    // Helper function to check signature validity with bytes memory
    function checkSignature(
        bytes memory signer,
        bytes32 hash,
        bytes memory signature
    ) internal view returns (bool) {
        return this.checkSignatureCalldata(signer, hash, signature);
    }

    // External function that uses calldata
    function checkSignatureCalldata(
        bytes calldata signer,
        bytes32 hash,
        bytes calldata signature
    ) external view returns (bool) {
        return SignatureCheckerExtended.isValidSignatureNow(signer, hash, signature);
    }

    // Helper wrappers for other library functions
    function isValidSignerFormat(bytes memory signer) internal view returns (bool) {
        return this.isValidSignerFormatCalldata(signer);
    }

    function isValidSignerFormatCalldata(bytes calldata signer) external pure returns (bool) {
        return SignatureCheckerExtended.isValidSignerFormat(signer);
    }

    function isERC7913Signer(bytes memory signer) internal view returns (bool) {
        return this.isERC7913SignerCalldata(signer);
    }

    function isERC7913SignerCalldata(bytes calldata signer) external pure returns (bool) {
        return SignatureCheckerExtended.isERC7913Signer(signer);
    }

    function decodeSigner(bytes memory signer) internal view returns (address, bytes memory) {
        return this.decodeSignerCalldata(signer);
    }

    function decodeSignerCalldata(bytes calldata signer) external pure returns (address, bytes memory) {
        (address verifier, bytes calldata key) = SignatureCheckerExtended.decodeSigner(signer);
        return (verifier, bytes(key));
    }

    function getVerifier(bytes memory signer) internal view returns (address) {
        return this.getVerifierCalldata(signer);
    }

    function getVerifierCalldata(bytes calldata signer) external pure returns (address) {
        return SignatureCheckerExtended.getVerifier(signer);
    }

    function setUp() public {
        testPrivateKey = 0x1234;
        testAddress = vm.addr(testPrivateKey);
        
        validVerifier = new MockVerifier(true);
        invalidVerifier = new MockVerifier(false);
    }

    /*//////////////////////////////////////////////////////////////
                            EOA TESTS
    //////////////////////////////////////////////////////////////*/

    function testEOAValidSignature() public {
        bytes32 hash = keccak256("test message");
        
        // Sign with EOA
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(testPrivateKey, hash);
        bytes memory signature = abi.encodePacked(r, s, v);
        
        // Encode signer (20 bytes for EOA)
        bytes memory signer = abi.encodePacked(testAddress);
        
        // Verify
        bool isValid = checkSignature(signer, hash, signature);
        assertTrue(isValid, "EOA signature should be valid");
    }

    function testEOAInvalidSignature() public {
        bytes32 hash = keccak256("test message");
        
        // Sign with different key
        uint256 wrongKey = 0x5678;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongKey, hash);
        bytes memory signature = abi.encodePacked(r, s, v);
        
        // Try to verify with testAddress
        bytes memory signer = abi.encodePacked(testAddress);
        
        bool isValid = checkSignature(signer, hash, signature);
        assertFalse(isValid, "Invalid EOA signature should fail");
    }

    /*//////////////////////////////////////////////////////////////
                        ERC-7913 TESTS
    //////////////////////////////////////////////////////////////*/

    function testERC7913ValidSignature() public {
        bytes32 hash = keccak256("test message");
        bytes memory key = "mock_public_key";
        bytes memory signature = "mock_signature";
        
        // Encode signer (verifier || key)
        bytes memory signer = abi.encodePacked(address(validVerifier), key);
        
        // Verify
        bool isValid = checkSignature(signer, hash, signature);
        assertTrue(isValid, "ERC-7913 signature should be valid");
    }

    function testERC7913InvalidSignature() public {
        bytes32 hash = keccak256("test message");
        bytes memory key = "mock_public_key";
        bytes memory signature = "mock_signature";
        
        // Encode signer with invalid verifier
        bytes memory signer = abi.encodePacked(address(invalidVerifier), key);
        
        // Verify
        bool isValid = checkSignature(signer, hash, signature);
        assertFalse(isValid, "Invalid ERC-7913 signature should fail");
    }

    /*//////////////////////////////////////////////////////////////
                        FORMAT VALIDATION TESTS
    //////////////////////////////////////////////////////////////*/

    function testInvalidSignerLengthTooShort() public {
        bytes memory signer = new bytes(19); // Less than 20
        bytes32 hash = keccak256("test");
        bytes memory signature = "sig";
        
        bool isValid = checkSignature(signer, hash, signature);
        assertFalse(isValid, "Should reject signer < 20 bytes");
    }

    function testIsValidSignerFormat() public {
        bytes memory validSigner = new bytes(20);
        assertTrue(isValidSignerFormat(validSigner));
        
        bytes memory invalidSigner = new bytes(19);
        assertFalse(isValidSignerFormat(invalidSigner));
    }

    function testIsERC7913Signer() public {
        bytes memory eoaSigner = new bytes(20);
        assertFalse(isERC7913Signer(eoaSigner));
        
        bytes memory erc7913Signer = new bytes(21);
        assertTrue(isERC7913Signer(erc7913Signer));
    }

    /*//////////////////////////////////////////////////////////////
                        ENCODING/DECODING TESTS
    //////////////////////////////////////////////////////////////*/

    function testEncodeSigner() public {
        address verifier = address(0x1234);
        bytes memory key = "test_key";
        
        bytes memory signer = SignatureCheckerExtended.encodeSigner(verifier, key);
        
        assertEq(signer.length, 20 + key.length);
        // Extract and verify verifier address from the first 20 bytes
        address extractedVerifier = getVerifier(signer);
        assertEq(extractedVerifier, verifier);
    }

    function testDecodeSigner() public {
        address verifier = address(0x1234);
        bytes memory key = "test_key";
        bytes memory signer = abi.encodePacked(verifier, key);
        
        (address decodedVerifier, bytes memory decodedKey) = 
            decodeSigner(signer);
        
        assertEq(decodedVerifier, verifier);
        assertEq(decodedKey, key);
    }

    function testDecodeSignerEOA() public {
        address addr = address(0x1234);
        bytes memory signer = abi.encodePacked(addr);
        
        (address decodedVerifier, bytes memory decodedKey) = 
            decodeSigner(signer);
        
        assertEq(decodedVerifier, addr);
        assertEq(decodedKey.length, 0);
    }

    function testGetVerifier() public {
        address verifier = address(0x1234);
        bytes memory key = "test_key";
        bytes memory signer = abi.encodePacked(verifier, key);
        
        address extractedVerifier = getVerifier(signer);
        assertEq(extractedVerifier, verifier);
    }

    /*//////////////////////////////////////////////////////////////
                        FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzzEncodeDecode(address verifier, bytes memory key) public {
        vm.assume(key.length > 0 && key.length < 1000);
        
        bytes memory signer = SignatureCheckerExtended.encodeSigner(verifier, key);
        (address decodedVerifier, bytes memory decodedKey) = 
            decodeSigner(signer);
        
        assertEq(decodedVerifier, verifier);
        assertEq(keccak256(decodedKey), keccak256(key));
    }

    function testFuzzValidSignerFormat(uint256 length) public {
        vm.assume(length < 10000);
        bytes memory signer = new bytes(length);
        
        bool expected = length >= 20;
        assertEq(isValidSignerFormat(signer), expected);
    }
}
