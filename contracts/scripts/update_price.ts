import { Buffer } from 'buffer';
import { writeFile, readFile } from 'fs/promises';
import { createHash } from 'crypto';
import type { OracleResponse } from './types.js';

// Check if --use-saved flag is present
const USE_SAVED_DATA = process.argv.includes('--use-saved');

/**
 * Computes single-field Merkle proof for a 5-leaf tree using SHA-256
 * Tree structure:
 *           Root
 *          /    \
 *        H01    H234
 *       /  \    /   \
 *      H0  H1  H23  H4
 *              /  \
 *             H2  H3
 *
 * For Field 4 (transcript commitment), proof = [H23, H01]
 */
function computeSingleFieldProof(
  allFieldHashes: Buffer[],
  leafIndex: number
): Buffer[] {
  if (allFieldHashes.length !== 5) {
    throw new Error(`Expected 5 field hashes, got ${allFieldHashes.length}`);
  }

  if (leafIndex !== 4) {
    throw new Error(`Only transcript commitment (index 4) is supported, got ${leafIndex}`);
  }

  const H0 = allFieldHashes[0];
  const H1 = allFieldHashes[1];
  const H2 = allFieldHashes[2];
  const H3 = allFieldHashes[3];

  // Tree structure for 5 leaves:
  //          Root
  //         /    \
  //     H0123     H4  <-- H4 is at index 1 at root level (right child)
  //     /   \
  //   H01   H23
  //  /  \  /  \
  // H0 H1 H2 H3

  // To prove H4 (leaf index 4):
  // At leaf level: H4 is alone on the right subtree
  // At root level: H4 (index 1, odd) is the right child, so we need left sibling H0123

  // Compute H01 = SHA256(H0 || H1)
  const H01 = createHash('sha256')
    .update(Buffer.concat([H0!, H1!]))
    .digest();

  // Compute H23 = SHA256(H2 || H3)
  const H23 = createHash('sha256')
    .update(Buffer.concat([H2!, H3!]))
    .digest();

  // Compute H0123 = SHA256(H01 || H23)
  const H0123 = createHash('sha256')
    .update(Buffer.concat([H01, H23]))
    .digest();

  console.log('   Computed H01:', H01.toString('hex'));
  console.log('   Computed H23:', H23.toString('hex'));
  console.log('   Computed H0123 (sibling of H4):', H0123.toString('hex'));

  // Verification: SHA256(H0123 || H4) should equal Root
  // Proof for H4 at index 4: just need H0123 as the left sibling
  return [H0123];
}

// Main function to fetch and parse the presentation
async function fetchAndParsePriceData() {
  try {
    let data: OracleResponse;

    if (USE_SAVED_DATA) {
      console.log('Using saved presentation data from presentation_data.json...');
      const savedData = JSON.parse(await readFile('presentation_data.json', 'utf-8'));

      // We need to serialize the header from the presentation
      // This will be done in the verification function
      data = {
        presentation_json: savedData.raw_presentation,
        presentation_bincode: savedData.presentation_bincode_base64,
        header_serialized: savedData.header_serialized || [], // Use saved or empty array
        verification: savedData.verification,
        field_hashes: []
      };
    } else {
      console.log('Fetching price data from oracle...');

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 60000); // 60 second timeout

      const response = await fetch('http://localhost:3000/price', {
        signal: controller.signal,
      }).finally(() => clearTimeout(timeoutId));

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      data = await response.json();
    }

    console.log('\n=== VERIFICATION RESULT ===');
    console.log('Verified:', data.verification.verified);
    console.log('Server:', data.verification.server);
    console.log('Timestamp:', data.verification.timestamp);
    console.log('Symbol:', data.verification.symbol);
    console.log('Price:', data.verification.price);
    console.log('Notary Public Key:', data.verification.notary_pubkey);


    // Print raw field hashes (these are 32-byte Blake3 hashes, not BCS-encoded)
    if (data.field_hashes && data.field_hashes.length > 0) {
      console.log('\n=== FIELD HASHES ===');
      data.field_hashes.forEach((hash, index) => {
        console.log(`Field ${index}: ${Buffer.from(hash).toString('hex')}`);
      });
    }
    // Parse presentation data
    const presentation = data.presentation_json;

    console.log('\n=== ATTESTATION DATA ===');
    const sigAlgName = presentation.attestation.signature.alg === 1 ? 'P256' :
                       presentation.attestation.signature.alg === 3 ? 'secp256k1' : 'Unknown';
    console.log('Signature Algorithm:', sigAlgName);
    console.log('Signature Length:', presentation.attestation.signature.data.length, 'bytes');

    // Get Notary's public key
    const verifyingKey = presentation.attestation.body.body.verifying_key;
    const notaryPubkeyHex = Buffer.from(verifyingKey.data.data).toString('hex');
    console.log('Notary Public Key (hex):', notaryPubkeyHex);

    // Get connection info
    const connInfo = presentation.attestation.body.body.connection_info;
    const timestamp = new Date(connInfo.data.time * 1000);
    console.log('Connection Time:', timestamp.toISOString());
    console.log('TLS Version:', connInfo.data.version);
    console.log('Transcript Length - Sent:', connInfo.data.transcript_length.sent);
    console.log('Transcript Length - Received:', connInfo.data.transcript_length.received);

    // Get transcript commitment
    const commitment = presentation.attestation.body.body.transcript_commitments[0];
    let rootHex: string | null = null;
    if (commitment && commitment.data.Encoding) {
      const root = commitment.data.Encoding.root;
      rootHex = Buffer.from(root.value).toString('hex');
      console.log('Transcript Commitment Root (hex):', rootHex);
    }

    console.log('\n=== SERVER IDENTITY ===');
    console.log('Server Name:', presentation.identity.name);
    console.log('Certificates Count:', presentation.identity.opening.data.certs.length);

    console.log('\n=== TRANSCRIPT DATA ===');
    const transcript = presentation.transcript.transcript;
    console.log('Sent Total:', transcript.sent_total, 'bytes');
    console.log('Received Total:', transcript.recv_total, 'bytes');
    console.log('Sent Authenticated:', transcript.sent_authed.length, 'bytes');
    console.log('Received Authenticated:', transcript.received_authed.length, 'bytes');

    // Parse sent data (HTTP request)
    const sentText = new TextDecoder().decode(new Uint8Array(transcript.sent_authed));
    console.log('\n=== HTTP REQUEST (Sent) ===');
    console.log(sentText);

    // Parse received data (HTTP response)
    const receivedBytes = transcript.received_authed;
    const receivedText = new TextDecoder().decode(new Uint8Array(receivedBytes));
    console.log('\n=== HTTP RESPONSE (Received) ===');
    console.log(receivedText);

    // Extract JSON body from response
    const jsonMatch = receivedText.match(/\r\n\r\n(.*)/s);
    if (jsonMatch && jsonMatch[1]) {
      const jsonBody = JSON.parse(jsonMatch[1]);
      console.log('\n=== PARSED PRICE DATA ===');
      console.log('Symbol:', jsonBody.symbol);
      console.log('Price:', jsonBody.price);
      console.log('Timestamp:', jsonBody.timestamp);
    }

    // === HASH PROOF DATA ===
    console.log('\n=== HASH PROOF DATA ===');
    console.log('Hash Algorithm:', data.hash_proof.hash_algorithm === 1 ? 'SHA256' : `Unknown (${data.hash_proof.hash_algorithm})`);
    console.log('Committed Hash:', Buffer.from(data.hash_proof.committed_hash).toString('hex'));
    console.log('Plaintext Length:', data.hash_proof.plaintext.length, 'bytes');
    console.log('Price Range:', `${data.hash_proof.price_range.start}-${data.hash_proof.price_range.end}`);
    console.log('Blinder:', Buffer.from(data.hash_proof.blinder).toString('hex'));
    console.log('Direction:', data.hash_proof.direction);

    // === MERKLE PROOF DATA ===
    console.log('\n=== BODY MERKLE PROOF ===');
    console.log('Root:', Buffer.from(data.body_merkle_proof.root).toString('hex'));
    console.log('Leaf Index:', data.body_merkle_proof.leaf_index);
    console.log('Proof Hashes Count:', data.body_merkle_proof.proof_hashes.length);
    console.log('Leaf Count:', data.body_merkle_proof.leaf_count);

    // === PREPARE DATA FOR SOLIDITY ===
    console.log('\n=== PREPARING SOLIDITY PROOF DATA ===');

    // Compute single-field Merkle proof off-chain
    console.log('\n=== COMPUTING MERKLE PROOF ===');
    console.log('All field hashes:', data.body_merkle_proof.all_field_hashes.length);
    const allFieldHashBuffers = data.body_merkle_proof.all_field_hashes.map(h => Buffer.from(h));
    const merkleProofHashes = computeSingleFieldProof(
      allFieldHashBuffers,
      data.body_merkle_proof.leaf_index
    );

    const solidityProof = {
      // Hash proof data
      plaintext: data.hash_proof.plaintext,
      plaintextHex: `0x${Buffer.from(data.hash_proof.plaintext).toString('hex')}`,
      blinder: Array.from(data.hash_proof.blinder),
      blinderHex: `0x${Buffer.from(data.hash_proof.blinder).toString('hex')}`,
      committedHash: `0x${Buffer.from(data.hash_proof.committed_hash).toString('hex')}`,
      priceStart: data.hash_proof.price_range.start,
      priceEnd: data.hash_proof.price_range.end,

      // Merkle proof data
      fieldHash: `0x${Buffer.from(data.body_merkle_proof.all_field_hashes[4]!).toString('hex')}`,
      merkleProofHashes: merkleProofHashes.map(h => `0x${h.toString('hex')}`),
      allFieldHashes: data.body_merkle_proof.all_field_hashes.map(h =>
        `0x${Buffer.from(h).toString('hex')}`
      ),
      leafIndex: data.body_merkle_proof.leaf_index,
      leafCount: data.body_merkle_proof.leaf_count,
      // Trim merkle root to 32 bytes (oracle may send 64 bytes with padding)
      merkleRoot: `0x${Buffer.from(data.body_merkle_proof.root).toString('hex').slice(0, 64)}`,

      // Signature data
      headerSerialized: Array.from(data.header_serialized),
      headerSerializedHex: `0x${Buffer.from(data.header_serialized).toString('hex')}`,
      signature: Array.from(presentation.attestation.signature.data),
      signatureHex: `0x${Buffer.from(presentation.attestation.signature.data).toString('hex')}`,
      notaryPubkey: Array.from(verifyingKey.data.data),
      notaryPubkeyHex: `0x${notaryPubkeyHex}`,

      // Metadata
      symbol: data.verification.symbol,
      price: data.verification.price,
      timestamp: data.verification.timestamp,
      server: data.verification.server,
    };

    console.log('Plaintext length:', solidityProof.plaintext.length);
    console.log('Blinder length:', solidityProof.blinder.length);
    console.log('Committed hash:', solidityProof.committedHash);
    console.log('Field hash (Field 4):', solidityProof.fieldHash);
    console.log('Merkle proof hashes:', solidityProof.merkleProofHashes.length, '- [H23, H01]');
    console.log('Header serialized length:', solidityProof.headerSerialized.length);
    console.log('Signature length:', solidityProof.signature.length);
    console.log('Notary pubkey length:', solidityProof.notaryPubkey.length);

    // Save proof data for Solidity contract testing
    await writeFile(
      'test/fixtures/proof_data.json',
      JSON.stringify(solidityProof, null, 2),
      'utf-8'
    );

    console.log('\n✅ Proof data saved to test/fixtures/proof_data.json');

  } catch (error) {
    if (error instanceof Error) {
      if (error.name === 'AbortError') {
        console.error('❌ Request timeout: Oracle server at http://localhost:3000/price did not respond within 10 seconds');
        console.error('   Make sure the oracle server is running on port 3000');
      } else if (error.message.includes('ECONNREFUSED') || error.message.includes('fetch failed')) {
        console.error('❌ Connection refused: Cannot connect to http://localhost:3000/price');
        console.error('   Make sure the oracle server is running on port 3000');
      } else {
        console.error('❌ Error fetching or parsing data:', error.message);
      }
    } else {
      console.error('❌ Unknown error:', error);
    }
    process.exit(1);
  }
}

// Run the main function
fetchAndParsePriceData().then(() => {
  process.exit(0);
}).catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
