// Type definitions based on TLSNotary Presentation structure
export interface OracleResponse {
  presentation_bincode: string;
  presentation_json: Presentation;
  verification: VerificationResult;
  header_serialized: number[];
  body_leaf_hashes: number[][];
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
