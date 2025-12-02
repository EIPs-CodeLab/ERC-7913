# ERC-7913: Signature Verifiers Implementation

A Solidity implementation of [EIP-7913](https://eips.ethereum.org/EIPS/eip-7913), enabling signature verification for address-less cryptographic keys.

## Abstract

Externally Owned Accounts (EOA) can sign messages with their associated private keys. Additionally [ERC-1271](https://eips.ethereum.org/EIPS/eip-1271) defines a method for signature verification by smart accounts such as multisig. In both cases the identity of the signer is an ethereum address. 

This standard extends the concept of signer description and signature verification to keys that do not have an ethereum identity of their own - they don't have their own address to represent them. This new mechanism can be used to integrate new signers such as:

- Non-ethereum cryptographic curves (P256/secp256r1, RSA, Ed25519, etc.)
- Hardware devices
- Email addresses
- ZK-based authentication

This is particularly relevant when dealing with account abstraction and social recovery of smart accounts.

## Motivation

With the development of account abstraction, there is an increasing need for non-ethereum signature verification. Cryptographic algorithms besides the natively supported secp256k1 are being used for controlling smart accounts. In particular:

- **secp256r1/P-256**: Supported by many mobile devices (like Apple's Secure Enclave and Android's StrongBox)
- **RSA keys**: Distributed by traditional institutions
- **ZK solutions**: For signing with emails or JWT from Web2 services

All these signature mechanisms have one thing in common: they do not have a canonical ethereum address to represent them onchain. While users could deploy ERC-1271 compatible contracts for each key individually, this would be cumbersome and expensive.

As account abstraction tries to separate account addresses (that hold assets) from the keys that control them, giving fixed on-chain addresses to keys is not the right approach. Instead, using a small number of verifier contracts that can process signatures in a standard way, and having accounts rely on these verifiers, is the correct approach.

Once the verifier is deployed, any key can be represented using a `(verifier, key)` pair without requiring any setup cost. The `(verifier, key)` pairs can be given permission to control a smart account, perform social recovery, or do any other operation without ever having a dedicated on-chain address.

This definition is backward compatible with EOA and ERC-1271 contracts: in that case, we use the address of the identity (EOA or contract) as the verifier and the key is empty.

## Features

- **ERC-7913 Interface**: Core interface for signature verifiers
- **P256 Verifier**: secp256r1/P-256 signature verification using RIP-7212 precompile
- **RSA Verifier**: RSA signature verification with PKCS#1 v1.5 padding
- **Extended Signature Checker**: Unified library supporting EOA, ERC-1271, and ERC-7913 signatures
- **Smart Account Example**: Reference implementation of a smart account using ERC-7913 signers

## Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation) installed

## Building the Project

### Installation

Clone the repository and install dependencies:

```bash
cd ERC-7913
forge install
```

### Compile

Build all smart contracts:

```bash
forge build
```


## Testing the Project

### Run All Tests

Execute the complete test suite:

```bash
forge test
```

**Expected output:**
- 6 tests in `P256VerifierTest`
- 13 tests in `SignatureCheckerExtendedTest`
- **Total: 19 tests passed**

### Run Tests with Detailed Output

For verbose output showing logs and traces:

```bash
forge test -vvv
```

Use different verbosity levels:
- `-v`: Show failed test details
- `-vv`: Show test names
- `-vvv`: Show test execution traces
- `-vvvv`: Show execution traces and setup
- `-vvvvv`: Show execution and setup with Stack traces

### Run Specific Test Files

Test only the P256 verifier:

```bash
forge test --match-path test/P256Verifier.t.sol
```

Test only the SignatureChecker library:

```bash
forge test --match-path test/SignatureCheckerExtended.t.sol
```

### Run Specific Test Functions

Run a single test by name:

```bash
forge test --match-test testERC7913ValidSignature
```

Run tests matching a pattern:

```bash
forge test --match-test "testERC7913*"
```

### Test Coverage

Generate a coverage report:

```bash
forge coverage
```

## Project Structure

```
ERC-7913/
├── src/
│   ├── interfaces/
│   │   └── IERC7913SignatureVerifier.sol    # EIP-7913 interface
│   ├── verifiers/
│   │   ├── P256Verifier.sol                 # P256/secp256r1 verifier
│   │   └── RSAVerifier.sol                  # RSA verifier
│   ├── libraries/
│   │   └── SignatureCheckerExtended.sol     # Extended signature checker
│   └── examples/
│       └── SmartAccountWithERC7913.sol      # Smart account example
├── test/
│   ├── P256Verifier.t.sol                   # P256 verifier tests
│   └── SignatureCheckerExtended.t.sol       # Library tests
├── lib/                                      # Dependencies (OpenZeppelin, Forge)
├── foundry.toml                             # Foundry configuration
└── README.md
```

## Usage Examples

### Using the P256 Verifier

```solidity
import {P256Verifier} from "./verifiers/P256Verifier.sol";
import {IERC7913SignatureVerifier} from "./interfaces/IERC7913SignatureVerifier.sol";

// Deploy verifier
P256Verifier verifier = new P256Verifier();

// Prepare inputs
bytes memory publicKey = ...; // 64 bytes: x || y coordinates
bytes32 hash = keccak256("message");
bytes memory signature = ...; // 64 bytes: r || s values

// Verify signature
bytes4 result = verifier.verify(publicKey, hash, signature);
bool isValid = (result == IERC7913SignatureVerifier.verify.selector);
```

### Using SignatureCheckerExtended

```solidity
import {SignatureCheckerExtended} from "./libraries/SignatureCheckerExtended.sol";

// For EOA (20 bytes)
bytes memory signer = abi.encodePacked(address(0x123...));

// For ERC-7913 verifier (>20 bytes: verifier address || key)
bytes memory signer = abi.encodePacked(verifierAddress, publicKey);

// Verify signature
bool isValid = SignatureCheckerExtended.isValidSignatureNow(
    signer,
    hash,
    signature
);
```

## Signer Format

The `SignatureCheckerExtended` library supports three formats:

| Format | Length | Structure | Description |
|--------|--------|-----------|-------------|
| EOA | 20 bytes | `address` | Standard Ethereum address |
| ERC-1271 | 20 bytes | `address` | Contract implementing ERC-1271 |
| ERC-7913 | >20 bytes | `verifier_address (20) \|\| key (variable)` | Verifier contract + public key |

## ERC-7913 Interface

The verifier interface follows [EIP-7913](https://eips.ethereum.org/EIPS/eip-7913):

```solidity
interface IERC7913SignatureVerifier {
    /**
     * @dev Verifies `signature` as a valid signature of `hash` by `key`.
     *
     * MUST return the bytes4 magic value 0x024ad318 (IERC7913SignatureVerifier.verify.selector) 
     * if the signature is valid.
     * 
     * SHOULD return 0xffffffff or revert if the signature is not valid.
     * SHOULD return 0xffffffff or revert if the key is empty.
     */
    function verify(
        bytes calldata key,
        bytes32 hash,
        bytes calldata signature
    ) external view returns (bytes4);
}
```

**Return values:**
- `0x024ad318` - Signature is valid (equals `verify.selector`)
- `0xffffffff` - Signature is invalid
- Reverts - Invalid input or verification failure

## Supported Cryptographic Schemes

| Scheme | Status | Precompile | Key Format | Signature Format |
|--------|--------|------------|------------|------------------|
| P256 (secp256r1) | Implemented | RIP-7212 (0x100) | 64 bytes (x\|\|y) | 64 bytes (r\|\|s) |
| RSA | Implemented | ModExp (0x05) | Variable | Variable |
| Ed25519 | Planned | - | - | - |
| BLS12-381 | Planned | - | - | - |

## Security Considerations

1. **P256 Precompile Dependency**: The P256Verifier requires the RIP-7212 precompile at address `0x100`. It will revert if the precompile is not available in your environment.

2. **RSA Gas Costs**: RSA verification is gas-intensive due to modular exponentiation. Always consider gas limits for on-chain usage.

3. **Input Validation**: Always validate key formats and signature lengths before verification to avoid unexpected behavior.

4. **Production Readiness**: This implementation is for demonstration and testing purposes. Conduct a thorough security audit before using in production.

5. **Key Management**: Ensure proper key generation and storage practices for all cryptographic schemes.

## Gas Usage

Approximate gas costs for signature verification:

| Operation | Gas Cost |
|-----------|----------|
| P256 verification (with precompile) | ~3,000-4,000 |
| P256 verification (without precompile) | Not implemented |
| RSA verification (2048-bit) | ~200,000-300,000 |
| EOA signature check | ~3,000-4,000 |

## Verification Flow

```
┌─────────────────────────┐
│  Signature + Signer     │
└───────────┬─────────────┘
            │
            ▼
    ┌───────────────┐
    │ Signer Length?│
    └───┬───────┬───┘
        │       │
    20 bytes    >20 bytes
        │       │
        ▼       ▼
    ┌─────┐  ┌──────────────────┐
    │ EOA │  │ Extract verifier │
    │  or │  │   & key from     │
    │1271 │  │   signer bytes   │
    └──┬──┘  └────────┬─────────┘
       │              │
       ▼              ▼
 ┌──────────┐  ┌────────────────┐
 │SignChecker│ │ Call verifier  │
 │.isValid.. │ │   .verify()    │
 └─────┬────┘  └────────┬───────┘
       │                │
       ▼                ▼
    ┌──────────────────────┐
    │   Return true/false   │
    └──────────────────────┘
```

## Common Issues

### P256 Precompile Not Available

```
Error: P256 precompile not available
```

**Solution**: The RIP-7212 precompile may not be deployed in your test environment. This is expected in standard Foundry tests. The precompile is available on certain networks that support RIP-7212.

### Compilation Warnings

Function state mutability warnings can be safely ignored - they suggest optimization opportunities but don't affect functionality.

## Contributing

Contributions are welcome! Areas for improvement:

- Additional cryptographic scheme implementations (Ed25519, BLS, etc.)
- Gas optimization for existing verifiers
- Comprehensive real-world test vectors
- Library fallback implementations for missing precompiles
- Enhanced documentation and examples

## License

MIT License

## References

- [EIP-7913: Signature Verifiers](https://eips.ethereum.org/EIPS/eip-7913)
- [RIP-7212: Precompile for secp256r1 Curve Support](https://github.com/ethereum/RIPs/blob/master/RIPS/rip-7212.md)
- [ERC-1271: Standard Signature Validation Method for Contracts](https://eips.ethereum.org/EIPS/eip-1271)
- [OpenZeppelin Contracts](https://github.com/OpenZeppelin/openzeppelin-contracts)

## Authors

Implementation based on EIP-7913 by:
- [@Amxx](https://github.com/Amxx)
- [@ernestognw](https://github.com/ernestognw)
- [@frangio](https://github.com/frangio)
- [@arr00](https://github.com/arr00)