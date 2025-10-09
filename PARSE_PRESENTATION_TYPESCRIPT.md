# Parsing TLSNotary Presentation in TypeScript

This guide shows how to parse the `presentation_json` data returned by the Binance Oracle Server.

## Response Structure

The server returns:
```typescript
interface OracleResponse {
  presentation_bincode: string;  // Base64-encoded bincode (for Noir)
  presentation_json: Presentation;  // JSON structure (for TypeScript)
  verification: VerificationResult;
}
```

## TypeScript Type Definitions

```typescript
interface Presentation {
  attestation: Attestation;
  identity: ServerIdentity;
  transcript: TranscriptProof;
}

interface Attestation {
  signature: Signature;
  header: Header;
  body: AttestationBody;
}

interface Signature {
  alg: number;  // 1 = P256
  data: number[];  // Raw signature bytes
}

interface Header {
  id: number[];  // Unique attestation ID
  root: Hash;    // Merkle root of the body
  version: number;
}

interface Hash {
  alg: number;  // 2 = Blake3
  value: number[];  // Hash bytes
}

interface AttestationBody {
  body: {
    verifying_key: VerifyingKey;
    connection_info: ConnectionInfo;
    server_ephemeral_key: ServerKey;
    cert_commitment: Hash;
    transcript_commitments: TranscriptCommitment[];
    extensions: any[];
  };
  proof: MerkleProof;
}

interface VerifyingKey {
  id: number;
  data: {
    alg: number;  // 1 = P256
    data: number[];  // Public key bytes (33 bytes compressed)
  };
}

interface ConnectionInfo {
  id: number;
  data: {
    time: number;  // Unix timestamp
    version: string;  // TLS version (e.g., "v1_2")
    transcript_length: {
      sent: number;
      received: number;
    };
  };
}

interface ServerKey {
  id: number;
  data: {
    type: string;  // "secp256r1"
    key: number[];  // 65 bytes (uncompressed point)
  };
}

interface TranscriptCommitment {
  id: number;
  data: {
    Encoding?: {
      root: Hash;
      secret: {
        seed: number[];
        delta: number[];
      };
    };
  };
}

interface ServerIdentity {
  name: string;  // "api.binance.com"
  opening: {
    blinder: number[];
    data: {
      certs: number[][];  // DER-encoded certificates
    };
  };
}

interface TranscriptProof {
  transcript: {
    sent_authed: number[];      // Authenticated sent bytes
    recv_authed: number[];      // Authenticated received bytes
    sent_total: number;
    recv_total: number;
    sent_idx: Range[];
    recv_idx: Range[];
  };
  encoding_proof: {
    openings: { [key: string]: Opening };
    inclusion_proof: MerkleProof;
  };
  hash_secrets: any[];
}

interface Range {
  start: number;
  end: number;
}

interface Opening {
  direction: "Sent" | "Received";
  idx: Range[];
  blinder: number[];
}

interface MerkleProof {
  alg: number;
  leaf_count: number;
  proof: {
    proof_hashes: number[][];
  };
}
```

## Example: Extracting Price Data

```typescript
async function getBinancePrice(): Promise<string> {
  const response = await fetch('http://localhost:3000/price');
  const data: OracleResponse = await response.json();

  // Method 1: Use the pre-verified data
  console.log('Verified price:', data.verification.price);

  // Method 2: Parse from raw transcript
  const transcript = data.presentation_json.transcript;

  // Convert received bytes to string
  const receivedBytes = transcript.transcript.received_authed;
  const receivedText = new TextDecoder().decode(new Uint8Array(receivedBytes));

  // Find the JSON body (after headers)
  const jsonMatch = receivedText.match(/\r\n\r\n(.*)/s);
  if (jsonMatch) {
    const jsonBody = JSON.parse(jsonMatch[1]);
    console.log('Symbol:', jsonBody.symbol);
    console.log('Price:', jsonBody.price);
    return jsonBody.price;
  }

  throw new Error('Failed to extract price');
}
```

## Example: Accessing Cryptographic Data

```typescript
function extractProofData(presentation: Presentation) {
  // Get the Notary's signature
  const signature = presentation.attestation.signature;
  console.log('Signature algorithm:', signature.alg === 1 ? 'P256' : 'Unknown');
  console.log('Signature bytes:', signature.data);

  // Get the transcript commitment (Merkle root)
  const commitment = presentation.attestation.body.body.transcript_commitments[0];
  if (commitment.data.Encoding) {
    const root = commitment.data.Encoding.root;
    console.log('Transcript commitment root:',
      Buffer.from(root.value).toString('hex'));
  }

  // Get the Notary's public key
  const verifyingKey = presentation.attestation.body.body.verifying_key;
  console.log('Notary pubkey:',
    Buffer.from(verifyingKey.data.data).toString('hex'));

  // Get the server name
  console.log('Server:', presentation.identity.name);

  // Get connection timestamp
  const connInfo = presentation.attestation.body.body.connection_info;
  const timestamp = new Date(connInfo.data.time * 1000);
  console.log('Connection time:', timestamp.toISOString());
}
```

## Example: Verifying Ranges

```typescript
function verifyTranscriptRanges(presentation: Presentation) {
  const transcript = presentation.transcript.transcript;

  // Check sent data range
  const sentRange = transcript.sent_idx[0];
  console.log(`Sent data: bytes ${sentRange.start}-${sentRange.end}`);
  console.log('Total sent:', transcript.sent_total);

  // Check received data range
  const recvRange = transcript.recv_idx[0];
  console.log(`Received data: bytes ${recvRange.start}-${recvRange.end}`);
  console.log('Total received:', transcript.recv_total);

  // Verify we revealed all data
  const allSentRevealed = sentRange.end === transcript.sent_total;
  const allRecvRevealed = recvRange.end === transcript.recv_total;

  console.log('All sent data revealed:', allSentRevealed);
  console.log('All received data revealed:', allRecvRevealed);
}
```

## For Noir Verification

If you're using the data in a Noir circuit, use `presentation_bincode`:

```typescript
// Get the bincode bytes for Noir
const bincodeBytes = Buffer.from(
  data.presentation_bincode,
  'base64'
);

// Pass to Noir circuit
const proof = await noir.prove({
  presentation: Array.from(bincodeBytes)
});
```

## Complete Example

```typescript
interface OracleResponse {
  presentation_bincode: string;
  presentation_json: any;
  verification: {
    verified: boolean;
    server: string;
    timestamp: string;
    symbol: string;
    price: string;
    notary_pubkey: string;
  };
}

async function main() {
  // Fetch proof from oracle
  const response = await fetch('http://localhost:3000/price');
  const data: OracleResponse = await response.json();

  // Quick access to verified data
  console.log('✅ Price:', data.verification.price);
  console.log('✅ Server:', data.verification.server);
  console.log('✅ Notary:', data.verification.notary_pubkey);

  // Access raw transcript
  const receivedBytes = data.presentation_json.transcript.transcript.received_authed;
  const receivedText = new TextDecoder().decode(new Uint8Array(receivedBytes));
  console.log('📄 HTTP Response:\n', receivedText.substring(0, 200));

  // Get bincode for Noir
  const bincodeBytes = Buffer.from(data.presentation_bincode, 'base64');
  console.log('🔐 Presentation size:', bincodeBytes.length, 'bytes');
}

main();
```

## Key Fields for Oracle Use Cases

For a price oracle, you typically need:

1. **Notary Public Key** (`presentation.attestation.body.body.verifying_key`)
   - Used to verify the signature on-chain

2. **Signature** (`presentation.attestation.signature`)
   - Cryptographic proof from the Notary

3. **Transcript Commitment** (`presentation.attestation.body.body.transcript_commitments[0]`)
   - Merkle root linking signature to HTTP data

4. **HTTP Response** (`presentation.transcript.transcript.received_authed`)
   - Contains the actual price JSON

5. **Merkle Proof** (`presentation.transcript.encoding_proof`)
   - Proves HTTP response is in the transcript commitment

All of these are accessible via the `presentation_json` field in a TypeScript-friendly format!
