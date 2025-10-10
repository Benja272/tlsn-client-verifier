import { bcs } from "@mysten/bcs";
import * as secp256k1 from "@noble/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { blake3 } from "@noble/hashes/blake3.js";
import type { Presentation } from "./types.js";

// Helper to compute 16-byte Blake3 prefix of a type name
function domainPrefix(typeName: string): Uint8Array {
  const fullHash = blake3(Buffer.from(typeName));
  return fullHash.slice(0, 16);
}

/**
 * Domain prefixes for each field type in `Body`.
 * These must match the Rust implementation:
 *   blake3::hash(stringify!(TypeName).as_bytes())[..16]
 */
export const DomainPrefixes: Record<string, Uint8Array> = {
  VerifyingKey: domainPrefix("VerifyingKey"),
  ConnectionInfo: domainPrefix("ConnectionInfo"),
  ServerEphemKey: domainPrefix("ServerEphemKey"),
  ServerCertCommitment: domainPrefix("ServerCertCommitment"),
  Extension: domainPrefix("Extension"),
  TranscriptCommitment: domainPrefix("TranscriptCommitment"),
};

// Define BCS schema for TypedHash
export const TypedHashSchema = bcs.struct("TypedHash", {
  alg: bcs.u8(),
  value: bcs.vector(bcs.u8()), // Vector with length prefix
});

export const HashSchema = bcs.struct("TypedHash", {
  value: bcs.vector(bcs.u8()),
  // len: bcs.u64(),
});

// Define BCS schema for Header
const HeaderSchema = bcs.struct("Header", {
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
  const verifyingKey =
    presentation.attestation.body.body.verifying_key.data.data;
  const signature = presentation.attestation.signature.data;
  const header = presentation.attestation.header;

  console.log("\n=== SIGNATURE VERIFICATION ===");
  console.log("1. Extracting data from presentation...");
  console.log("   Notary pubkey length:", verifyingKey.length, "bytes");
  console.log("   Signature length:", signature.length, "bytes");

  // 2. Serialize header using BCS
  console.log("\n2. Serializing header with BCS...");
  let headerBytes: Uint8Array;

  if (rustHeaderSerialized) {
    // Use the serialized header from Rust
    headerBytes = new Uint8Array(rustHeaderSerialized);
    console.log("   Using Rust-serialized header");
    console.log("   Serialized header length:", headerBytes.length, "bytes");
    console.log(
      "   Serialized header (hex):",
      Buffer.from(headerBytes).toString("hex")
    );

    // Also serialize with our TypeScript implementation for comparison
    const tsHeaderBytes = serializeHeader(header);
    console.log("\n   Comparing with TypeScript BCS serialization:");
    console.log(
      "   TS header (hex):",
      Buffer.from(tsHeaderBytes).toString("hex")
    );

    if (
      Buffer.from(headerBytes).toString("hex") ===
      Buffer.from(tsHeaderBytes).toString("hex")
    ) {
      console.log("   ✅ Serializations match!");
    } else {
      console.log("   ❌ Serializations differ!");
    }
  } else {
    // Use our TypeScript BCS serialization
    headerBytes = serializeHeader(header);
    console.log("   Serialized header length:", headerBytes.length, "bytes");
    console.log(
      "   Serialized header (hex):",
      Buffer.from(headerBytes).toString("hex")
    );
  }

  // 3. Parse signature (r, s are 32 bytes each)
  console.log("\n3. Parsing signature (r, s)...");
  const r = Buffer.from(signature.slice(0, 32)).toString("hex");
  const s = Buffer.from(signature.slice(32, 64)).toString("hex");
  console.log("   r:", r);
  console.log("   s:", s);

  // 4. Verify signature using Ethereum-compatible signing (secp256k1 + Keccak-256)
  console.log("\n4. Verifying ECDSA secp256k1 signature with Keccak-256...");
  const pubkeyHex = Buffer.from(verifyingKey).toString("hex");
  console.log("   Pubkey (hex):", pubkeyHex);

  let isValid = false;
  let messageHash: Uint8Array | undefined;
  try {
    // Ethereum-compatible signature verification:
    // 1. Hash the message with Keccak-256
    // 2. Verify the signature against the hash

    // Signature is 65 bytes: r (32) || s (32) || v (1)
    // Strip the recovery byte (v) for verification - only need r || s
    const signatureBytes =
      signature.length === 65
        ? new Uint8Array(signature.slice(0, 64))
        : new Uint8Array(signature);
    const publicKeyBytes = new Uint8Array(verifyingKey);

    console.log(
      "   Signature length after stripping recovery byte:",
      signatureBytes.length
    );

    // Hash the header with Keccak-256 (Ethereum-compatible)
    messageHash = keccak_256(headerBytes);
    console.log(
      "   Keccak-256 hash:",
      Buffer.from(messageHash).toString("hex")
    );

    // Verify signature with @noble/secp256k1
    // prehash: false because we're passing the already-computed Keccak-256 hash
    isValid = secp256k1.verify(signatureBytes, messageHash, publicKeyBytes, {
      prehash: false,
    });

    if (isValid) {
      console.log("   ✅ SIGNATURE VALID!");
    } else {
      console.log("   ❌ SIGNATURE INVALID!");
      // Debug output
      console.log("   Debug - Signature length:", signatureBytes.length);
      console.log("   Debug - Message hash length:", messageHash.length);
      console.log("   Debug - Public key length:", publicKeyBytes.length);
    }
  } catch (error) {
    console.error("   ❌ Verification error:", error);
    isValid = false;
  }

  return {
    isValid,
    details: {
      notaryPubkey: pubkeyHex,
      signatureHex: Buffer.from(signature).toString("hex"),
      headerBytes: Buffer.from(headerBytes).toString("hex"),
      messageHash: messageHash ? Buffer.from(messageHash).toString("hex") : "",
      headerInfo: {
        id: Buffer.from(header.id).toString("hex"),
        version: header.version,
        rootAlg: header.root.alg,
        rootValue: Buffer.from(header.root.value).toString("hex"),
      },
    },
  };
}

/**
 * Extracts and displays all verification-related information
 */
export function displayVerificationInfo(presentation: Presentation): void {
  console.log("\n=== CRYPTOGRAPHIC PROOF CHAIN ===");

  // Header info
  const header = presentation.attestation.header;
  console.log("\n📋 HEADER:");
  console.log("   ID:", Buffer.from(header.id).toString("hex"));
  console.log("   Version:", header.version);
  console.log(
    "   Root Algorithm:",
    header.root.alg === 2 ? "Blake3" : "Unknown"
  );
  console.log("   Root Value:", Buffer.from(header.root.value).toString("hex"));

  // Body commitments
  console.log("\n🔐 ATTESTATION BODY:");
  const body = presentation.attestation.body.body;

  // Transcript commitment
  const commitment = body.transcript_commitments[0];
  if (commitment && commitment.data.Encoding) {
    const transcriptRoot = commitment.data.Encoding.root;
    console.log(
      "   Transcript Commitment Root:",
      Buffer.from(transcriptRoot.value).toString("hex")
    );
    console.log(
      "   Commitment Algorithm:",
      transcriptRoot.alg === 2 ? "Blake3" : "Unknown"
    );
  }

  // Connection info
  console.log("\n🔗 CONNECTION INFO:");
  console.log(
    "   Time:",
    new Date(body.connection_info.data.time * 1000).toISOString()
  );
  console.log("   TLS Version:", body.connection_info.data.version);
  console.log(
    "   Sent bytes:",
    body.connection_info.data.transcript_length.sent
  );
  console.log(
    "   Received bytes:",
    body.connection_info.data.transcript_length.received
  );

  // Transcript data
  console.log("\n📝 TRANSCRIPT DATA:");
  const transcript = presentation.transcript.transcript;
  console.log(
    "   Sent ranges:",
    transcript.sent_idx.map((r) => `${r.start}-${r.end}`).join(", ")
  );
  console.log(
    "   Received ranges:",
    transcript.recv_idx.map((r) => `${r.start}-${r.end}`).join(", ")
  );

  // Proof chain explanation
  console.log("\n⛓️  PROOF CHAIN:");
  console.log("   1. Notary signs Header (ECDSA secp256k1 + Keccak-256)");
  console.log("   2. Header.root commits to Body (Merkle proof)");
  console.log(
    "   3. Body.transcript_commitments commits to HTTP data (Merkle proof)"
  );
  console.log("   4. HTTP response contains the price data");
  console.log("\n   By verifying the signature, we prove the entire chain!");
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
  const verifyingKey =
    presentation.attestation.body.body.verifying_key.data.data;
  const signatureRaw = presentation.attestation.signature.data;

  console.log("\n=== PREPARING NOIR CIRCUIT INPUTS ===");

  // Strip recovery byte if present (65 bytes -> 64 bytes)
  const signature =
    signatureRaw.length === 65 ? signatureRaw.slice(0, 64) : signatureRaw;

  console.log(
    "   Signature length:",
    signature.length,
    "(recovery byte stripped if present)"
  );

  // Decompress the public key (33 bytes compressed -> 65 bytes uncompressed)
  const compressedPubkey = new Uint8Array(verifyingKey);
  const uncompressedPubkey = secp256k1.Point.fromHex(
    Buffer.from(compressedPubkey).toString("hex")
  ).toHex(false);
  const uncompressedBytes = Buffer.from(uncompressedPubkey, "hex");

  // Extract x and y coordinates (skip first byte which is 0x04 prefix)
  const pub_key_x = Array.from(uncompressedBytes.slice(1, 33)) as number[];
  const pub_key_y = Array.from(uncompressedBytes.slice(33, 65)) as number[];

  console.log(
    "   Compressed pubkey:",
    Buffer.from(compressedPubkey).toString("hex")
  );
  console.log("   Uncompressed pubkey:", uncompressedPubkey);
  console.log("   pub_key_x:", Array.from(pub_key_x).join(', '));
  console.log("   pub_key_y:", Array.from(pub_key_y).join(', '));

  return {
    pub_key_x,
    pub_key_y,
    signature: Array.from(signature) as number[],
    header_serialized: headerSerialized,
  };
}

/**
 * Hash data with domain separation (Blake3)
 * This matches the Rust `hash_separated` function
 */
function hashSeparated(
  typeName: keyof typeof DomainPrefixes,
  data: Uint8Array
): Uint8Array {
  const prefix = DomainPrefixes[typeName]!;
  const combined = new Uint8Array(prefix.length + data.length);
  combined.set(prefix);
  combined.set(bcs.bytes(data.length).serialize(data).toBytes(), prefix.length);
  return blake3(combined);
}

/**
 * Calculate tree depth for Merkle tree
 * Equivalent to: floor(log2(n)) + 1
 */
function treeDepth(leavesCount: number): number {
  if (leavesCount === 0) return 0;
  if (leavesCount === 1) return 1;
  // Count leading zeros in binary representation, then calculate depth
  // This is equivalent to: floor(log2(n)) + 1
  return Math.floor(Math.log2(leavesCount)) + 1;
}

/**
 * Hash two nodes together using Blake3
 */
function hashNodes(left: Uint8Array, right: Uint8Array): Uint8Array {
  const combined = new Uint8Array(left.length + right.length);
  combined.set(left);
  combined.set(right, left.length);
  return blake3(combined);
}

/**
 * Verify Merkle proof
 * Handles uneven number of leaves (odd node passes to next layer unchanged)
 */
function verifyMerkleProof(
  leaves: Uint8Array[],
  proofHashes: Uint8Array[],
  totalLeaves: number,
  expectedRoot: Uint8Array
): boolean {
  if (leaves.length === 0) return false;

  const depth = treeDepth(totalLeaves);
  console.log(`   Tree depth: ${depth} for ${totalLeaves} total leaves`);
  console.log(`   Verifying ${leaves.length} leaves`);

  // Build the tree bottom-up
  let currentLayer = [...leaves];
  let proofIndex = 0;

  // Keep hashing until we have a single root
  let layerNum = 0;
  while (currentLayer.length > 1) {
    console.log(`   Layer ${layerNum}: ${currentLayer.length} nodes`);
    const nextLayer: Uint8Array[] = [];

    for (let i = 0; i < currentLayer.length; i += 2) {
      const leftNode = currentLayer[i];
      const rightNode = currentLayer[i + 1];

      if (!leftNode) continue; // Safety check

      if (rightNode) {
        // We have a pair - hash them together
        const combined = hashNodes(leftNode, rightNode);
        nextLayer.push(combined);
        console.log(`     Hashed nodes ${i} and ${i + 1}`);
      } else {
        // Odd node - it passes to next layer unchanged
        nextLayer.push(leftNode);
        console.log(`     Passed odd node ${i} to next layer`);
      }
    }

    // Add any proof hashes needed for this level
    // (This is for sparse proofs where we don't have all leaves)
    while (proofIndex < proofHashes.length) {
      const proofHash = proofHashes[proofIndex++];
      if (proofHash) {
        nextLayer.push(proofHash);
      }
    }

    console.log(`     Next layer will have ${nextLayer.length} nodes`);
    currentLayer = nextLayer;
    layerNum++;
  }

  // Should have exactly one root
  if (currentLayer.length !== 1) {
    console.log(`   ❌ Expected 1 root, got ${currentLayer.length}`);
    return false;
  }

  const computedRoot = currentLayer[0];
  if (!computedRoot) {
    console.log(`   ❌ No root computed`);
    return false;
  }

  const rootsMatch = Buffer.from(computedRoot).equals(
    Buffer.from(expectedRoot)
  );

  console.log(`   Computed root: ${Buffer.from(computedRoot).toString("hex")}`);
  console.log(`   Expected root: ${Buffer.from(expectedRoot).toString("hex")}`);

  return rootsMatch;
}

/**
 * Verifies the body commitment using Merkle proof
 * This matches the Rust `verify_with_provider` and `hash_fields` functions
 */
export function verifyBodyCommitment(presentation: Presentation): boolean {
  const body = presentation.attestation.body.body;
  const header = presentation.attestation.header;
  const proof = presentation.attestation.body.proof;

  console.log("\n=== BODY COMMITMENT VERIFICATION ===");

  try {
    // 1. Hash all body fields with domain separation
    const fields: Array<{ id: number; hash: Uint8Array }> = [];

    // Serialize and hash each field
    // verifying_key
    console.log("   Hashing verifying_key...");
    console.log(
      "   verifying_key.data:",
      JSON.stringify(body.verifying_key.data).substring(0, 100)
    );
    const vkSchema = bcs.struct("VerifyingKeyData", {
      alg: bcs.u8(),
      data: bcs.vector(bcs.u8()),
    });
    const vkData = vkSchema
      .serialize({
        alg: body.verifying_key.data.alg,
        data: body.verifying_key.data.data,
      })
      .toBytes();
    fields.push({
      id: body.verifying_key.id,
      hash: hashSeparated("VerifyingKey", vkData),
    });

    console.log("vk serialized");
    // connection_info
    const connInfoSchema = bcs.struct("ConnectionInfo", {
      time: bcs.u64(),
      version: bcs.string(),
      transcript_length: bcs.struct("TranscriptLength", {
        sent: bcs.u64(),
        received: bcs.u64(),
      }),
    });
    const connInfoData = connInfoSchema
      .serialize(body.connection_info.data)
      .toBytes();
    console.log("conn info serialized");
    fields.push({
      id: body.connection_info.id,
      hash: hashSeparated("ConnectionInfo", connInfoData),
    });

    // server_ephemeral_key
    const sekSchema = bcs.struct("ServerEphemeralKey", {
      type: bcs.string(),
      key: bcs.vector(bcs.u8()),
    });
    const sekData = sekSchema
      .serialize(body.server_ephemeral_key.data)
      .toBytes();
    console.log("sek serialized");
    fields.push({
      id: body.server_ephemeral_key.id,
      hash: hashSeparated("ServerEphemKey", sekData),
    });

    // cert_commitment
    console.log(
      "   cert_commitment structure:",
      JSON.stringify(body.cert_commitment).substring(0, 150)
    );
    const certCommitSchema = bcs.struct("CertCommit", {
      alg: bcs.u8(),
      value: bcs.vector(bcs.u8()),
    });
    const certCommitData = certCommitSchema
      .serialize({
        alg: body.cert_commitment.data.alg,
        value: body.cert_commitment.data.value,
      })
      .toBytes();
    console.log("cerCommitment serialized");
    fields.push({
      id: body.cert_commitment.id,
      hash: hashSeparated("ServerCertCommitment", certCommitData),
    });

    // extensions (if any)
    for (const ext of body.extensions) {
      const extData = bcs.vector(bcs.u8()).serialize(ext.data).toBytes();
      fields.push({ id: ext.id, hash: hashSeparated("Extension", extData) });
    }

    // transcript_commitments
    for (const tc of body.transcript_commitments) {
      if (tc.data.Encoding) {
        const tcSchema = bcs.struct("TranscriptCommitmentEncoding", {
          root: bcs.struct("TypedHash", {
            alg: bcs.u8(),
            value: bcs.vector(bcs.u8()),
          }),
          secret: bcs.struct("Secret", {
            seed: bcs.vector(bcs.u8()),
            delta: bcs.vector(bcs.u8()),
          }),
        });
        const tcData = tcSchema.serialize(tc.data.Encoding).toBytes();
        fields.push({
          id: tc.id,
          hash: hashSeparated("TranscriptCommitment", tcData),
        });
      }
    }

    // 2. Sort fields by ID
    fields.sort((a, b) => a.id - b.id);

    console.log(`   Hashed ${fields.length} body fields`);
    fields.forEach((f) => {
      console.log(`   Field ${f.id}: ${Buffer.from(f.hash).toString("hex")}`);
    });

    // 3. Verify Merkle proof
    console.log("\n   Verifying Merkle proof...");
    console.log(
      `   Header root: ${Buffer.from(header.root.value).toString("hex")}`
    );
    console.log(`   Merkle proof leaf count: ${proof.leaf_count}`);
    console.log(`   Proof hashes: ${proof.proof.proof_hashes.length}`);

    // The leaves need to be the raw hash values (32 bytes each from Blake3)
    const leafHashes = fields.map((f) => f.hash);

    if (leafHashes[0]) {
      console.log(
        `   Leaf 0 (raw): ${Buffer.from(leafHashes[0])
          .toString("hex")
          .substring(0, 32)}...`
      );
    }

    const isValid = verifyMerkleProof(
      leafHashes,
      proof.proof.proof_hashes.map((h) => new Uint8Array(h)),
      proof.leaf_count,
      new Uint8Array(header.root.value)
    );

    if (isValid) {
      console.log("   ✅ Merkle proof VALID!");
      return true;
    } else {
      console.log("   ❌ Merkle proof INVALID!");
      return false;
    }
  } catch (error) {
    console.error("   ❌ Body commitment verification error:", error);
    if (error instanceof Error) {
      console.error("   Error message:", error.message);
      console.error("   Stack:", error.stack);
    }
    return false;
  }
}
