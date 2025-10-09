import { bcs } from '@mysten/bcs';
import * as secp256k1 from '@noble/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3.js';
import type { Presentation } from './types.js';

// Define BCS schema for TypedHash
const TypedHashSchema = bcs.struct('TypedHash', {
  alg: bcs.u8(),
  value: bcs.vector(bcs.u8()), // Vector with length prefix
});

// Define BCS schema for Header
const HeaderSchema = bcs.struct('Header', {
  id: bcs.fixedArray(16, bcs.u8()), // Fixed-size array (16 bytes), not vector
  version: bcs.u32(), // u32, not u16
  root: TypedHashSchema,
});

/**
 * Serializes the Header using BCS (Binary Canonical Serialization)
 * This must match the Rust implementation exactly
 */
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

/**
 * Verifies the Notary's ECDSA secp256k1 signature on the attestation header
 *
 * @param presentation - The TLSNotary presentation data
 * @param rustHeaderSerialized - Optional: Header bytes from Rust for comparison
 * @returns Object containing verification result and details
 */
export async function verifyNotarySignature(
  presentation: Presentation,
  rustHeaderSerialized?: number[]
): Promise<{
  isValid: boolean;
  details: {
    notaryPubkey: string;
    signatureHex: string;
    headerBytes: string;
    messageHash: string;
    headerInfo: {
      id: string;
      version: number;
      rootAlg: number;
      rootValue: string;
    };
  };
}> {
  // 1. Extract cryptographic data
  const verifyingKey = presentation.attestation.body.body.verifying_key.data.data;
  const signature = presentation.attestation.signature.data;
  const header = presentation.attestation.header;

  console.log('\n=== SIGNATURE VERIFICATION ===');
  console.log('1. Extracting data from presentation...');
  console.log('   Notary pubkey length:', verifyingKey.length, 'bytes');
  console.log('   Signature length:', signature.length, 'bytes');

  // 2. Serialize header using BCS
  console.log('\n2. Serializing header with BCS...');
  let headerBytes: Uint8Array;

  if (rustHeaderSerialized) {
    // Use the serialized header from Rust
    headerBytes = new Uint8Array(rustHeaderSerialized);
    console.log('   Using Rust-serialized header');
    console.log('   Serialized header length:', headerBytes.length, 'bytes');
    console.log('   Serialized header (hex):', Buffer.from(headerBytes).toString('hex'));

    // Also serialize with our TypeScript implementation for comparison
    const tsHeaderBytes = serializeHeader(header);
    console.log('\n   Comparing with TypeScript BCS serialization:');
    console.log('   TS header (hex):', Buffer.from(tsHeaderBytes).toString('hex'));

    if (Buffer.from(headerBytes).toString('hex') === Buffer.from(tsHeaderBytes).toString('hex')) {
      console.log('   ✅ Serializations match!');
    } else {
      console.log('   ❌ Serializations differ!');
    }
  } else {
    // Use our TypeScript BCS serialization
    headerBytes = serializeHeader(header);
    console.log('   Serialized header length:', headerBytes.length, 'bytes');
    console.log('   Serialized header (hex):', Buffer.from(headerBytes).toString('hex'));
  }

  // 3. Parse signature (r, s are 32 bytes each)
  console.log('\n3. Parsing signature (r, s)...');
  const r = Buffer.from(signature.slice(0, 32)).toString('hex');
  const s = Buffer.from(signature.slice(32, 64)).toString('hex');
  console.log('   r:', r);
  console.log('   s:', s);

  // 4. Verify signature using Ethereum-compatible signing (secp256k1 + Keccak-256)
  console.log('\n4. Verifying ECDSA secp256k1 signature with Keccak-256...');
  const pubkeyHex = Buffer.from(verifyingKey).toString('hex');
  console.log('   Pubkey (hex):', pubkeyHex);

  let isValid = false;
  let messageHash: Uint8Array | undefined;
  try {
    // Ethereum-compatible signature verification:
    // 1. Hash the message with Keccak-256
    // 2. Verify the signature against the hash

    // Signature is 65 bytes: r (32) || s (32) || v (1)
    // Strip the recovery byte (v) for verification - only need r || s
    const signatureBytes = signature.length === 65
      ? new Uint8Array(signature.slice(0, 64))
      : new Uint8Array(signature);
    const publicKeyBytes = new Uint8Array(verifyingKey);

    console.log('   Signature length after stripping recovery byte:', signatureBytes.length);

    // Hash the header with Keccak-256 (Ethereum-compatible)
    messageHash = keccak_256(headerBytes);
    console.log('   Keccak-256 hash:', Buffer.from(messageHash).toString('hex'));

    // Verify signature with @noble/secp256k1
    // prehash: false because we're passing the already-computed Keccak-256 hash
    isValid = secp256k1.verify(signatureBytes, messageHash, publicKeyBytes, { prehash: false });

    if (isValid) {
      console.log('   ✅ SIGNATURE VALID!');
    } else {
      console.log('   ❌ SIGNATURE INVALID!');
      // Debug output
      console.log('   Debug - Signature length:', signatureBytes.length);
      console.log('   Debug - Message hash length:', messageHash.length);
      console.log('   Debug - Public key length:', publicKeyBytes.length);
    }
  } catch (error) {
    console.error('   ❌ Verification error:', error);
    isValid = false;
  }

  return {
    isValid,
    details: {
      notaryPubkey: pubkeyHex,
      signatureHex: Buffer.from(signature).toString('hex'),
      headerBytes: Buffer.from(headerBytes).toString('hex'),
      messageHash: messageHash ? Buffer.from(messageHash).toString('hex') : '',
      headerInfo: {
        id: Buffer.from(header.id).toString('hex'),
        version: header.version,
        rootAlg: header.root.alg,
        rootValue: Buffer.from(header.root.value).toString('hex'),
      },
    },
  };
}

/**
 * Extracts and displays all verification-related information
 */
export function displayVerificationInfo(presentation: Presentation): void {
  console.log('\n=== CRYPTOGRAPHIC PROOF CHAIN ===');

  // Header info
  const header = presentation.attestation.header;
  console.log('\n📋 HEADER:');
  console.log('   ID:', Buffer.from(header.id).toString('hex'));
  console.log('   Version:', header.version);
  console.log('   Root Algorithm:', header.root.alg === 2 ? 'Blake3' : 'Unknown');
  console.log('   Root Value:', Buffer.from(header.root.value).toString('hex'));

  // Body commitments
  console.log('\n🔐 ATTESTATION BODY:');
  const body = presentation.attestation.body.body;

  // Transcript commitment
  const commitment = body.transcript_commitments[0];
  if (commitment && commitment.data.Encoding) {
    const transcriptRoot = commitment.data.Encoding.root;
    console.log('   Transcript Commitment Root:', Buffer.from(transcriptRoot.value).toString('hex'));
    console.log('   Commitment Algorithm:', transcriptRoot.alg === 2 ? 'Blake3' : 'Unknown');
  }

  // Connection info
  console.log('\n🔗 CONNECTION INFO:');
  console.log('   Time:', new Date(body.connection_info.data.time * 1000).toISOString());
  console.log('   TLS Version:', body.connection_info.data.version);
  console.log('   Sent bytes:', body.connection_info.data.transcript_length.sent);
  console.log('   Received bytes:', body.connection_info.data.transcript_length.received);

  // Transcript data
  console.log('\n📝 TRANSCRIPT DATA:');
  const transcript = presentation.transcript.transcript;
  console.log('   Sent ranges:', transcript.sent_idx.map(r => `${r.start}-${r.end}`).join(', '));
  console.log('   Received ranges:', transcript.recv_idx.map(r => `${r.start}-${r.end}`).join(', '));

  // Proof chain explanation
  console.log('\n⛓️  PROOF CHAIN:');
  console.log('   1. Notary signs Header (ECDSA secp256k1 + Keccak-256)');
  console.log('   2. Header.root commits to Body (Merkle proof)');
  console.log('   3. Body.transcript_commitments commits to HTTP data (Merkle proof)');
  console.log('   4. HTTP response contains the price data');
  console.log('\n   By verifying the signature, we prove the entire chain!');
}

/**
 * Prepares Noir circuit inputs
 * Decompresses the public key and formats all inputs for the Noir circuit
 */
export function prepareNoirInputs(
  presentation: Presentation,
  headerSerialized: number[]
): {
  pub_key_x: number[];
  pub_key_y: number[];
  signature: number[];
  header_serialized: number[];
} {
  const verifyingKey = presentation.attestation.body.body.verifying_key.data.data;
  const signatureRaw = presentation.attestation.signature.data;

  console.log('\n=== PREPARING NOIR CIRCUIT INPUTS ===');

  // Strip recovery byte if present (65 bytes -> 64 bytes)
  const signature = signatureRaw.length === 65
    ? signatureRaw.slice(0, 64)
    : signatureRaw;

  console.log('   Signature length:', signature.length, '(recovery byte stripped if present)');

  // Decompress the public key (33 bytes compressed -> 65 bytes uncompressed)
  const compressedPubkey = new Uint8Array(verifyingKey);
  const uncompressedPubkey = secp256k1.Point.fromHex(Buffer.from(compressedPubkey).toString('hex')).toHex(false);
  const uncompressedBytes = Buffer.from(uncompressedPubkey, 'hex');

  // Extract x and y coordinates (skip first byte which is 0x04 prefix)
  const pub_key_x = Array.from(uncompressedBytes.slice(1, 33)) as number[];
  const pub_key_y = Array.from(uncompressedBytes.slice(33, 65)) as number[];

  console.log('   Compressed pubkey:', Buffer.from(compressedPubkey).toString('hex'));
  console.log('   Uncompressed pubkey:', uncompressedPubkey);
  console.log('   pub_key_x:', Buffer.from(pub_key_x).toString('hex'));
  console.log('   pub_key_y:', Buffer.from(pub_key_y).toString('hex'));

  return {
    pub_key_x,
    pub_key_y,
    signature: Array.from(signature) as number[],
    header_serialized: headerSerialized,
  };
}
