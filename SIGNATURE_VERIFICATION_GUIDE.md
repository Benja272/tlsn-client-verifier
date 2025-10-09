# TLSNotary Signature Verification Guide

This guide explains how to verify the Notary's signature in a Noir circuit or any cryptographic verification system.

## What Gets Signed

The Notary signs the **Header** using their P256 private key. The signature proves that the Notary attested to specific TLS session data.

### Signature Verification Steps (from crates/core/src/attestation/proof.rs:62-68)

```rust
signature_verifier.verify(
    &body.verifying_key.data,        // Notary's public key (33 bytes compressed P256)
    &CanonicalSerialize::serialize(&self.header),  // Message that was signed
    &self.signature.data,            // Signature (64 bytes)
)
```

## Header Structure

The Header contains (from [crates/core/src/attestation.rs:133-140](crates/core/src/attestation.rs#L133)):

```rust
pub struct Header {
    pub id: Uid,              // 16 bytes - unique attestation ID
    pub version: Version,     // 2 bytes - version number (currently 0)
    pub root: TypedHash,      // 34 bytes - Merkle root of the body
}
```

**Total**: ~52 bytes before serialization

## Canonical Serialization (BCS)

The Header is serialized using **BCS** (Binary Canonical Serialization) before signing.

From [crates/core/src/serialize.rs:13-16](crates/core/src/serialize.rs#L13):
```rust
fn serialize(&self) -> Vec<u8> {
    bcs::to_bytes(self).unwrap()
}
```

BCS is the serialization format used by the Diem blockchain and Sui. It ensures deterministic byte representation.

## Extracting Data from presentation_json

### 1. Get the Notary's Public Key

```typescript
const verifyingKey = presentation.attestation.body.body.verifying_key;
const pubkeyBytes = verifyingKey.data.data;  // 33 bytes (compressed P256)

console.log('Notary pubkey:', Buffer.from(pubkeyBytes).toString('hex'));
// Example: 03de5ed9b4ae608b467fb7f1fb4faa9d625cddcee5534860a5d3102d500420d2fc
```

### 2. Get the Signature

```typescript
const signature = presentation.attestation.signature;
const signatureAlg = signature.alg;  // 1 = P256
const signatureBytes = signature.data;  // 64 bytes (r, s)

console.log('Signature algorithm:', signatureAlg === 1 ? 'P256' : 'Unknown');
console.log('Signature:', Buffer.from(signatureBytes).toString('hex'));
```

### 3. Get the Header

```typescript
const header = presentation.attestation.header;

const headerId = header.id;           // 16 bytes
const headerVersion = header.version;  // 0
const headerRoot = header.root;        // TypedHash

console.log('Header ID:', Buffer.from(headerId).toString('hex'));
console.log('Header version:', headerVersion);
console.log('Header root alg:', headerRoot.alg);  // 2 = Blake3
console.log('Header root:', Buffer.from(headerRoot.value).toString('hex'));
```

## BCS Serialization in TypeScript

To verify the signature, you need to serialize the Header using BCS:

```typescript
import { bcs } from '@mysten/bcs';

// Define the BCS schema for Header
const HeaderSchema = bcs.struct('Header', {
  id: bcs.vector(bcs.u8()),      // 16 bytes
  version: bcs.u16(),             // 2 bytes (little-endian)
  root: bcs.struct('TypedHash', {
    alg: bcs.u8(),                // 1 byte (2 = Blake3)
    value: bcs.vector(bcs.u8()),  // 32 bytes
  }),
});

// Serialize the header
function serializeHeader(header: any): Uint8Array {
  return HeaderSchema.serialize({
    id: header.id,
    version: header.version,
    root: {
      alg: header.root.alg,
      value: header.root.value,
    },
  }).toBytes();
}

// Example usage
const headerBytes = serializeHeader(presentation.attestation.header);
console.log('Serialized header:', Buffer.from(headerBytes).toString('hex'));
```

**Install BCS library:**
```bash
npm install @mysten/bcs
```

## Verification Formula

```
ECDSA_P256_Verify(
  public_key = verifying_key.data.data,    // 33 bytes
  message = BCS_serialize(header),          // Variable length (~52 bytes)
  signature = signature.data                // 64 bytes (r || s)
)
```

## Complete TypeScript Example

```typescript
import { bcs } from '@mysten/bcs';
import * as elliptic from 'elliptic';

const EC = elliptic.ec;
const p256 = new EC('p256');

// Define BCS schema
const TypedHashSchema = bcs.struct('TypedHash', {
  alg: bcs.u8(),
  value: bcs.vector(bcs.u8()),
});

const HeaderSchema = bcs.struct('Header', {
  id: bcs.vector(bcs.u8()),
  version: bcs.u16(),
  root: TypedHashSchema,
});

function verifyNotarySignature(presentation: any): boolean {
  // 1. Extract data
  const verifyingKey = presentation.attestation.body.body.verifying_key.data.data;
  const signature = presentation.attestation.signature.data;
  const header = presentation.attestation.header;

  // 2. Serialize header using BCS
  const headerBytes = HeaderSchema.serialize({
    id: header.id,
    version: header.version,
    root: {
      alg: header.root.alg,
      value: header.root.value,
    },
  }).toBytes();

  // 3. Hash the serialized header (P256 ECDSA uses SHA256)
  const crypto = require('crypto');
  const messageHash = crypto.createHash('sha256').update(headerBytes).digest();

  // 4. Parse signature (r, s are 32 bytes each)
  const r = Buffer.from(signature.slice(0, 32)).toString('hex');
  const s = Buffer.from(signature.slice(32, 64)).toString('hex');

  // 5. Parse public key
  const pubkey = p256.keyFromPublic(Buffer.from(verifyingKey), 'compressed');

  // 6. Verify signature
  const isValid = pubkey.verify(messageHash, { r, s });

  console.log('✅ Signature valid:', isValid);
  return isValid;
}

// Usage
async function main() {
  const response = await fetch('http://localhost:3000/price');
  const data = await response.json();

  const isValid = verifyNotarySignature(data.presentation_json);
  console.log('Signature verification:', isValid ? 'PASSED ✅' : 'FAILED ❌');
}
```

**Install dependencies:**
```bash
npm install @mysten/bcs elliptic @types/elliptic
```

## For Noir Circuit Implementation

In Noir, you'll need to:

### 1. Define the Header Structure

```noir
struct TypedHash {
    alg: u8,
    value: [u8; 32],
}

struct Header {
    id: [u8; 16],
    version: u16,
    root: TypedHash,
}
```

### 2. Implement BCS Serialization

BCS serialization for Header:
- `id`: length prefix (1 byte) + 16 bytes
- `version`: 2 bytes (little-endian u16)
- `root.alg`: 1 byte
- `root.value`: length prefix (1 byte) + 32 bytes

```noir
fn serialize_header(header: Header) -> [u8; MAX_HEADER_SIZE] {
    let mut bytes = [0; MAX_HEADER_SIZE];
    let mut offset = 0;

    // Serialize id (length-prefixed vector)
    bytes[offset] = 16;  // Length of id
    offset += 1;
    for i in 0..16 {
        bytes[offset + i] = header.id[i];
    }
    offset += 16;

    // Serialize version (little-endian u16)
    bytes[offset] = (header.version & 0xFF) as u8;
    bytes[offset + 1] = ((header.version >> 8) & 0xFF) as u8;
    offset += 2;

    // Serialize root.alg
    bytes[offset] = header.root.alg;
    offset += 1;

    // Serialize root.value (length-prefixed vector)
    bytes[offset] = 32;  // Length of value
    offset += 1;
    for i in 0..32 {
        bytes[offset + i] = header.root.value[i];
    }
    offset += 32;

    bytes
}
```

### 3. Verify ECDSA Signature

```noir
use dep::std::ecdsa_secp256r1;

fn verify_notary_signature(
    pubkey: [u8; 33],        // Compressed P256 public key
    header: Header,
    signature: [u8; 64],     // r || s (32 bytes each)
) -> bool {
    // 1. Serialize header
    let header_bytes = serialize_header(header);

    // 2. Hash with SHA256
    let message_hash = std::hash::sha256(header_bytes);

    // 3. Extract r and s from signature
    let mut r = [0; 32];
    let mut s = [0; 32];
    for i in 0..32 {
        r[i] = signature[i];
        s[i] = signature[32 + i];
    }

    // 4. Decompress public key (if needed by your ECDSA lib)
    let pubkey_uncompressed = decompress_p256_pubkey(pubkey);

    // 5. Verify ECDSA signature
    let is_valid = ecdsa_secp256r1::verify_signature(
        pubkey_uncompressed,
        signature,
        message_hash
    );

    is_valid
}
```

### 4. Main Circuit

```noir
fn main(
    // Inputs from presentation_json
    notary_pubkey: pub [u8; 33],
    header_id: [u8; 16],
    header_version: u16,
    header_root_alg: u8,
    header_root_value: [u8; 32],
    signature: [u8; 64],

    // Expected values to verify
    expected_price: pub Field,
) {
    // Reconstruct header
    let header = Header {
        id: header_id,
        version: header_version,
        root: TypedHash {
            alg: header_root_alg,
            value: header_root_value,
        },
    };

    // Verify Notary signature
    let sig_valid = verify_notary_signature(notary_pubkey, header, signature);
    assert(sig_valid);

    // ... rest of circuit (verify Merkle proofs, extract price, etc.)
}
```

## What the Signature Proves

When you verify the Notary's signature over the Header, you prove:

1. ✅ **Notary Attestation**: The Notary (identified by `verifying_key`) attested to this data
2. ✅ **Data Integrity**: The `header.root` (Merkle root) commits to all the attestation body fields
3. ✅ **Commitment Chain**:
   - Signature → Header
   - Header.root → Body (via Merkle proof)
   - Body.transcript_commitments → HTTP data (via Merkle proof)

This creates a cryptographic chain from the Notary's signature all the way to the HTTP response containing the price!

## Data Flow Summary

```
Binance API Response (JSON with price)
  ↓
[Merkle commitment via encoding_proof]
  ↓
Transcript Commitment (Merkle root)
  ↓
[Included in Body, hashed into header.root]
  ↓
Header (id, version, root)
  ↓
[BCS serialized + SHA256 hashed]
  ↓
ECDSA P256 Signature
  ↓
Notary's Private Key
```

To verify in reverse:
1. Verify signature on Header ✅ (proves Notary signed it)
2. Verify Body Merkle proof ✅ (proves Body is in Header.root)
3. Verify Transcript Merkle proof ✅ (proves HTTP data is in Transcript Commitment)
4. Extract price from HTTP response ✅

All of this can be done in a Noir circuit for on-chain verification!
