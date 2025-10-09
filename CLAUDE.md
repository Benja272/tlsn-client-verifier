# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a TypeScript client for verifying TLSNotary presentations using cryptographic signature verification and zero-knowledge proofs (ZKPs) with Noir circuits. The project consumes TLSNotary proofs from an oracle server and performs both traditional ECDSA signature verification and ZKP verification.

**Core Technology Stack:**
- TypeScript with ES modules (`"type": "module"`)
- Noir circuits for ZK proofs (using Barretenberg backend via `@aztec/bb.js`)
- BCS (Binary Canonical Serialization) for data serialization
- ECDSA secp256k1 signature verification (Ethereum-compatible)
- Keccak-256 hashing

## Commands

### Development
```bash
# Run the main TLSNotary presentation verification (fetches from oracle, verifies, generates ZK proof)
npm start

# Compile and test the Noir circuit (basic test without real data)
npm run compile
```

### Noir Circuit Development
The Noir circuit lives in `circuits/verifier/`:

```bash
# Navigate to circuit directory
cd circuits/verifier

# Compile the Noir circuit (creates target/verifier.json)
nargo compile

# Run circuit tests
nargo test

# Execute circuit with inputs from Prover.toml
nargo execute
```

## Architecture

### Data Flow

1. **Oracle Communication** ([src/index.ts](src/index.ts)):
   - Fetches TLSNotary presentation from `http://localhost:3000/price`
   - Receives `OracleResponse` with three key parts:
     - `presentation_json`: Human-readable TypeScript types
     - `presentation_bincode`: For Noir circuit input
     - `header_serialized`: BCS-serialized header from Rust (for exact verification)

2. **Cryptographic Verification** ([src/verify.ts](src/verify.ts)):
   - BCS serialization of Header struct (must match Rust implementation exactly)
   - ECDSA secp256k1 signature verification using `@noble/secp256k1`
   - Uses Keccak-256 hash (Ethereum-compatible, NOT SHA-256)
   - Verifies Notary's signature over the attestation header

3. **Zero-Knowledge Proof** ([circuits/verifier/src/main.nr](circuits/verifier/src/main.nr)):
   - Proves signature validity without revealing private signature
   - Uses UltraHonk proving system with 4 threads
   - Circuit inputs: uncompressed public key (x, y), signature (64 bytes), serialized header (54 bytes)
   - Outputs ZK proof that can be verified on-chain

### Cryptographic Proof Chain

The verification establishes this cryptographic chain:

```
Notary's Private Key
  → ECDSA Signature (secp256k1)
    → Header (BCS serialized, Keccak-256 hashed)
      → Header.root (Merkle commitment)
        → Attestation Body
          → Transcript Commitments
            → HTTP Response Data (from api.binance.com)
```

By verifying the Notary's signature on the Header, the entire chain is cryptographically proven.

### Key Files

- **[src/types.ts](src/types.ts)**: TypeScript type definitions matching TLSNotary's Rust structures
- **[src/verify.ts](src/verify.ts)**: BCS serialization and ECDSA verification logic
- **[src/index.ts](src/index.ts)**: Main entry point orchestrating fetch → verify → ZK proof generation
- **[circuits/verifier/src/main.nr](circuits/verifier/src/main.nr)**: Noir circuit for ZK signature verification

### BCS Serialization Details

The Header struct is serialized using BCS (Binary Canonical Serialization):

```typescript
struct Header {
  id: [u8; 16],        // Fixed-size array (NOT vector with length prefix)
  version: u32,        // Little-endian u32 (NOT u16)
  root: TypedHash,
}

struct TypedHash {
  alg: u8,
  value: [u8; 32],     // Vector with length prefix (1 byte + 32 bytes)
}
```

**Total serialized size**: 54 bytes
- `id`: 16 bytes (no length prefix, it's a fixed array)
- `version`: 4 bytes (u32 little-endian)
- `root.alg`: 1 byte
- `root.value`: 1 byte length + 32 bytes = 33 bytes

**Critical**: The TypeScript BCS serialization must exactly match the Rust implementation. The oracle provides `header_serialized` for verification purposes.

### Signature Verification - Important Details

**DO NOT use SHA-256 or P256 curve.** This project uses:
- **Curve**: secp256k1 (same as Ethereum)
- **Hash**: Keccak-256 (NOT SHA-256)
- **Format**: 64-byte signature (r || s, no v/recovery id needed for verification)
- **Public Key**: 33 bytes compressed, decompressed to 64 bytes (x, y coordinates) for Noir

The Notary signs: `sign(keccak256(bcs_serialize(header)))`

### Working with the Oracle Server

The client expects a running oracle server at `http://localhost:3000/price` that returns:
```typescript
{
  presentation_json: Presentation,
  presentation_bincode: string,        // Base64-encoded
  header_serialized: number[],         // BCS bytes from Rust
  verification: {
    verified: boolean,
    server: string,
    timestamp: string,
    symbol: string,
    price: string,
    notary_pubkey: string
  }
}
```

## Documentation Files

- **[PARSE_PRESENTATION_TYPESCRIPT.md](PARSE_PRESENTATION_TYPESCRIPT.md)**: Guide for parsing TLSNotary presentation JSON structure
- **[SIGNATURE_VERIFICATION_GUIDE.md](SIGNATURE_VERIFICATION_GUIDE.md)**: Deep dive into BCS serialization, ECDSA verification, and Noir circuit implementation

## TypeScript Configuration

- **Module system**: ESM with `"type": "module"` in package.json
- **Target**: ESNext
- **Strict mode**: Enabled with extra strictness (`noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`)
- **JSON imports**: Use `with { type: 'json' }` syntax for JSON imports
- **File extensions**: All imports must use `.js` extension (not `.ts`) due to ESM requirements

## Common Pitfalls

1. **BCS Serialization**: Do not modify the BCS schema without understanding the Rust implementation. The `id` field is a fixed array, not a vector.
2. **Hash Function**: Always use Keccak-256, not SHA-256. This is Ethereum-compatible signing.
3. **Public Key Format**: The verifying key from the presentation is 33 bytes compressed. For Noir, decompress to 65 bytes (skip 0x04 prefix, extract x and y).
4. **Noir Circuit Compilation**: After modifying [circuits/verifier/src/main.nr](circuits/verifier/src/main.nr), run `nargo compile` in the circuit directory to regenerate [circuits/verifier/target/verifier.json](circuits/verifier/target/verifier.json).
5. **Header Size**: The serialized header is exactly 54 bytes. If this changes, update the circuit's fixed-size array.

## Dependencies

Key dependencies and their purposes:
- `@aztec/bb.js`: Barretenberg backend for UltraHonk ZK proofs
- `@noir-lang/noir_js`: Noir circuit execution in TypeScript
- `@mysten/bcs`: BCS serialization (compatible with Rust's BCS)
- `@noble/secp256k1`: ECDSA secp256k1 signature verification
- `@noble/hashes`: Keccak-256 hashing
- `tsx`: TypeScript execution without separate compilation step
