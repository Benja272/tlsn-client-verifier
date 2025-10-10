import { Buffer } from 'buffer';
import { writeFile, readFile } from 'fs/promises';
import type { OracleResponse } from './types.js';
import { verifyNotarySignature, displayVerificationInfo, prepareNoirInputs, verifyBodyCommitment, TypedHashSchema, HashSchema } from './verify.js';
import { Noir } from '@noir-lang/noir_js';
import { UltraHonkBackend } from '@aztec/bb.js';
import verifierCircuit from '../circuits/verifier/target/verifier.json' with { type: 'json' };

// Check if --use-saved flag is present
const USE_SAVED_DATA = process.argv.includes('--use-saved');

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
        body_leaf_hashes: []
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


    data.body_leaf_hashes.forEach((hash)=>{
      // console.log(HashSchema.parse(Buffer.from(hash)).value)
      console.log(Buffer.from(hash).toString('hex'))
    })
    data.body_leaf_hashes.forEach((hash)=>{
      console.log(Buffer.from(HashSchema.parse(Buffer.from(hash)).value).toString('hex'))
      // console.log(Buffer.from(bcs.bytes(hash.length).parse(Buffer.from(hash))).toString('hex'))
    })
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

    // === CRYPTOGRAPHIC VERIFICATION ===
    // Display detailed verification information
    displayVerificationInfo(presentation);

    // Verify the body commitment
    verifyBodyCommitment(presentation);

    // Verify the Notary's signature (using Rust-serialized header if available)
    const verificationResult = await verifyNotarySignature(
      presentation,
      data.header_serialized
    );

    console.log('\n' + '='.repeat(50));
    if (verificationResult.isValid) {
      console.log('🎉 SIGNATURE VERIFICATION: PASSED ✅');
      console.log('The Notary signature is cryptographically valid!');
    } else {
      console.log('❌ SIGNATURE VERIFICATION: FAILED');
      console.log('The signature could not be verified!');
    }
    console.log('='.repeat(50));

    // === NOIR ZERO-KNOWLEDGE PROOF ===
    let proofData: any = null;
    if (verificationResult.isValid) {
      console.log('\n=== GENERATING NOIR ZK PROOF ===');

      // Prepare inputs for Noir circuit
      const noirInputs = prepareNoirInputs(presentation, data.header_serialized);

      // Initialize Noir circuit
      const noir = new Noir(verifierCircuit as any);
      const backend = new UltraHonkBackend(verifierCircuit.bytecode as any, { threads: 4 }, { recursive: false });

      console.log('\nGenerating witness... ⏳');
      const { witness } = await noir.execute(noirInputs);
      console.log(`Witness size: ${witness.length}`);

      console.log('\nGenerating proof... ⏳');
      const proof = await backend.generateProof(witness, {keccakZK: true});
      console.log('Generated proof ✅');
      console.log(`Proof bytes length: ${proof.proof.length}`);
      console.log(`Expected proof length: ${507 * 32} (507 * 32)`);
      console.log(`Public inputs count: ${proof.publicInputs?.length || 0}`);

      console.log('\nVerifying proof... ⌛');
      const isValidProof = await backend.verifyProof(proof, {keccakZK: true});

      console.log('\n' + '='.repeat(50));
      if (isValidProof) {
        console.log('🎉 NOIR ZK PROOF: VALID ✅');
        console.log('The zero-knowledge proof is valid!');

        // Prepare proof data for Solidity contract
        // The proof object from bb.js contains the proof bytes and public inputs
        console.log('\nProof object keys:', Object.keys(proof));
        console.log('Proof.proof type:', typeof proof.proof);
        console.log('Proof.publicInputs', proof.publicInputs);

        proofData = {
          proof: Array.from(proof.proof),
          proofHex: Buffer.from(proof.proof).toString('hex'),
          publicInputs: proof.publicInputs,
          price: data.verification.price,
        };
      } else {
        console.log('❌ NOIR ZK PROOF: INVALID');
      }
      console.log('='.repeat(50));
    }

    // Prepare data to save
    const outputData = {
      verification: data.verification,
      header_serialized: data.header_serialized, // Save header_serialized for testing
      cryptographic_data: {
        notary_pubkey: notaryPubkeyHex,
        signature_algorithm: sigAlgName,
        signature_bytes: presentation.attestation.signature.data,
        transcript_commitment_root: rootHex,
        connection_timestamp: timestamp.toISOString(),
        tls_version: connInfo.data.version,
      },
      server_identity: {
        name: presentation.identity.name,
        certificates_count: presentation.identity.opening.data.certs.length,
      },
      transcript: {
        sent_data: sentText,
        received_data: receivedText,
        sent_total: transcript.sent_total,
        received_total: transcript.recv_total,
      },
      raw_presentation: presentation,
      presentation_bincode_base64: data.presentation_bincode,
    };

    // Save to file
    await writeFile(
      'presentation_data.json',
      JSON.stringify(outputData, null, 2),
      'utf-8'
    );

    console.log('\n✅ Data saved to presentation_data.json');

    // Save proof data for Solidity contract testing
    if (proofData) {
      await writeFile(
        'contracts/test/fixtures/proof_data.json',
        JSON.stringify(proofData, null, 2),
        'utf-8'
      );
      console.log('✅ Proof data saved to contracts/test/fixtures/proof_data.json');
    }

    return outputData;

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
