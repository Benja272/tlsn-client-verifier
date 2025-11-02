// Type definitions based on TLSNotary Presentation structure

export interface HashProofData {
  hash_algorithm: number;        // 1 = SHA256
  committed_hash: number[];      // 32 bytes
  plaintext: string;             // Full HTTP response
  price_range: { start: number; end: number };
  blinder: number[];             // 16 bytes
  direction: string;             // "Sent" or "Received"
}

export interface BodyMerkleProof {
  root: number[];                // 32 bytes (from header)
  all_field_hashes: number[][];  // All 5 field hashes from oracle
  leaf_index: number;            // Position in field_hashes (should be 4)
  leaf_count: number;            // Total leaves in tree (should be 5)
  proof_hashes: number[][];      // Sibling hashes (empty from oracle, computed off-chain)
}

export interface OracleResponse {
  presentation_bincode: string;
  presentation_json: Presentation;
  verification: VerificationResult;
  header_serialized: number[];
  field_hashes: number[][];
  hash_proof: HashProofData;
  body_merkle_proof: BodyMerkleProof;
}

export interface VerificationResult {
  verified: boolean;
  server: string;
  timestamp: string;
  symbol: string;
  price: string;
  notary_pubkey: string;
}

export interface Presentation {
  attestation: Attestation;
  identity: ServerIdentity;
  transcript: TranscriptProof;
}

export interface Attestation {
  signature: Signature;
  header: Header;
  body: AttestationBody;
}

export interface Signature {
  alg: number;
  data: number[];
}

export interface Header {
  id: number[];
  root: Hash;
  version: number;
}

export interface Hash {
  alg: number;
  value: number[];
}

export interface AttestationBody {
  body: {
    verifying_key: VerifyingKey;
    connection_info: ConnectionInfo;
    server_ephemeral_key: ServerKey;
    cert_commitment: {
      id: number;
      data: Hash;
    };
    transcript_commitments: TranscriptCommitment[];
    extensions: any[];
  };
  proof: MerkleProof;
}

export interface VerifyingKey {
  id: number;
  data: {
    alg: number;
    data: number[];
  };
}

export interface ConnectionInfo {
  id: number;
  data: {
    time: number;
    version: string;
    transcript_length: {
      sent: number;
      received: number;
    };
  };
}

export interface ServerKey {
  id: number;
  data: {
    type: string;
    key: number[];
  };
}

export interface TranscriptCommitment {
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

export interface ServerIdentity {
  name: string;
  opening: {
    blinder: number[];
    data: {
      certs: number[][];
      handshake?: {
        v1_2?: {
          client_random: number[];
          server_ephemeral_key: {
            key: number[];
            type: string;
          };
          server_random: number[];
        };
      };
      sig?: {
        scheme: string;
        sig: number[];
      };
    };
  };
}

export interface TranscriptProof {
  transcript: {
    sent_authed: number[];
    received_authed: number[];
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

export interface Range {
  start: number;
  end: number;
}

export interface Opening {
  direction: "Sent" | "Received";
  idx: Range[];
  blinder: number[];
}

export interface MerkleProof {
  alg: number;
  leaf_count: number;
  proof: {
    proof_hashes: number[][];
  };
}
