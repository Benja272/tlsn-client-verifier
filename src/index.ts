import { Buffer } from 'buffer';
import { writeFile } from 'fs/promises';
import type { OracleResponse } from './types.js';
import { verifyNotarySignature, displayVerificationInfo, prepareNoirInputs } from './verify.js';
import { Noir } from '@noir-lang/noir_js';
import { UltraHonkBackend } from '@aztec/bb.js';
import verifierCircuit from '../circuits/verifier/target/verifier.json' with { type: 'json' };

// Main function to fetch and parse the presentation
async function fetchAndParsePriceData() {
  try {
    console.log('Fetching price data from oracle...');

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout

    const response = await fetch('http://localhost:3000/price', {
      signal: controller.signal,
    }).finally(() => clearTimeout(timeoutId));

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data: OracleResponse = await response.json();

    console.log('\n=== VERIFICATION RESULT ===');
    console.log('Verified:', data.verification.verified);
    console.log('Server:', data.verification.server);
    console.log('Timestamp:', data.verification.timestamp);
    console.log('Symbol:', data.verification.symbol);
    console.log('Price:', data.verification.price);
    console.log('Notary Public Key:', data.verification.notary_pubkey);

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
      const proof = await backend.generateProof(witness);
      console.log('Generated proof ✅');
      console.log(`Proof bytes length: ${proof.proof.length}`);

      console.log('\nVerifying proof... ⌛');
      const isValidProof = await backend.verifyProof(proof);

      console.log('\n' + '='.repeat(50));
      if (isValidProof) {
        console.log('🎉 NOIR ZK PROOF: VALID ✅');
        console.log('The zero-knowledge proof is valid!');
      } else {
        console.log('❌ NOIR ZK PROOF: INVALID');
      }
      console.log('='.repeat(50));
    }

    // Prepare data to save
    const outputData = {
      verification: data.verification,
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
fetchAndParsePriceData();
