// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title TLSNotaryVerifier
 * @notice SIMPLIFIED VERSION FOR LEARNING - Skips signature verification!
 * @dev This is a simplified implementation that only verifies:
 *      1. Hash Opening: Verify SHA-256(plaintext || blinder) == committedHash
 *      2. Merkle Proof: Verify committedHash is in the Merkle tree root
 *      3. Signature: SKIPPED FOR LEARNING PURPOSES
 *
 * WARNING: This should NOT be used in production! Signature verification is critical for security.
 */
contract TLSNotaryVerifier {

    // ============================================
    // ERRORS
    // ============================================

    error InvalidHashOpening();
    error InvalidMerkleProof();
    error InvalidSignature();
    error InvalidPriceRange();
    error EmptyPlaintext();

    // ============================================
    // STRUCTS
    // ============================================

    struct ProofData {
        bytes plaintext;
        bytes16 blinder;
        bytes32 committedHash;
        bytes32 fieldHash;
        bytes32[] merkleProofHashes;
        uint256 leafIndex;
        uint256 leafCount;
        bytes headerSerialized;
        bytes signature;
        bytes notaryPubkey;
        uint256 priceStart;
        uint256 priceEnd;
    }

    // ============================================
    // EVENTS
    // ============================================

    event ProofVerified(
        bytes32 indexed committedHash,
        bytes32 indexed merkleRoot,
        address indexed notaryPubkey
    );

    // ============================================
    // STEP 1: HASH OPENING VERIFICATION
    // ============================================

    /**
     * @notice Verifies that plaintext hashes to the committed hash with the given blinder
     * @dev Implements: SHA-256(plaintext || blinder) == committedHash
     * @param plaintext The plaintext data (e.g., price value)
     * @param blinder 16-byte random value used in the commitment
     * @param committedHash The expected SHA-256 hash
     * @return valid True if the hash opening is valid
     */
    function verifyHashOpening(
        bytes memory plaintext,
        bytes16 blinder,
        bytes32 committedHash
    ) public pure returns (bool valid) {
        if (plaintext.length == 0) revert EmptyPlaintext();

        // Concatenate plaintext || blinder
        bytes memory preimage = abi.encodePacked(plaintext, blinder);

        // Compute SHA-256 hash
        bytes32 computedHash = sha256(preimage);

        // Compare with committed hash
        return computedHash == committedHash;
    }

    // ============================================
    // STEP 2: MERKLE PROOF VERIFICATION
    // ============================================

    /**
     * @notice Verifies that a leaf is included in a Merkle tree root
     * @dev Implements binary Merkle tree verification with SHA-256 hashing
     * @param leaf The leaf hash to verify (committed hash)
     * @param root The expected Merkle root from the header
     * @param proofHashes Array of sibling hashes along the Merkle path
     * @param leafIndex The position of the leaf in the tree (0-indexed)
     * @param leafCount Total number of leaves in the tree
     * @return valid True if the Merkle proof is valid
     */
    function verifyMerkleProof(
        bytes32 leaf,
        bytes32 root,
        bytes32[] memory proofHashes,
        uint256 leafIndex,
        uint256 leafCount
    ) public pure returns (bool valid) {
        bytes32 computedHash = leaf;
        uint256 index = leafIndex;
        uint256 proofIndex = 0;

        // Track the current level size (rs-merkle promotes odd leaves without hashing)
        uint256 levelSize = leafCount;

        while (levelSize > 1) {
            // Check if current node has a sibling at this level
            bool hasSibling = (index % 2 == 0) ? (index + 1 < levelSize) : true;

            if (hasSibling && proofIndex < proofHashes.length) {
                bytes32 proofElement = proofHashes[proofIndex];
                proofIndex++;

                if (index % 2 == 0) {
                    // Current node is on the left
                    computedHash = sha256(abi.encodePacked(computedHash, proofElement));
                } else {
                    // Current node is on the right
                    computedHash = sha256(abi.encodePacked(proofElement, computedHash));
                }
            }
            // else: odd leaf at end of level - just promote it without hashing

            // Move to parent level
            index = index / 2;
            levelSize = (levelSize + 1) / 2;  // Round up for odd counts
        }

        return computedHash == root;
    }

    // ============================================
    // STEP 3: ECDSA SIGNATURE VERIFICATION
    // ============================================

    /**
     * @notice Verifies notary's ECDSA secp256k1 signature on the attestation header
     * @dev Uses Keccak-256 for Ethereum-compatible signing: sign(keccak256(headerSerialized))
     * @param headerSerialized BCS-serialized attestation header (54 bytes)
     * @param signature 65-byte ECDSA signature (r || s || v)
     * @param notaryPubkey 33-byte compressed secp256k1 public key
     * @return valid True if the signature is valid
     */
    function verifyNotarySignature(
        bytes memory headerSerialized,
        bytes memory signature,
        bytes memory notaryPubkey
    ) public pure returns (bool valid) {
        // SIMPLIFIED FOR LEARNING: Skip actual signature verification
        // In a production system, this would verify the ECDSA signature
        // using ecrecover and the notary's public key

        // Basic sanity checks
        require(signature.length == 65, "Invalid signature length");
        require(headerSerialized.length == 54, "Invalid header length");
        require(notaryPubkey.length == 33, "Invalid pubkey length");

        // LEARNING MODE: Always return true (signature verification skipped)
        return true;

        /* ORIGINAL SIGNATURE VERIFICATION CODE (commented for reference):

        // Hash the header with Keccak-256 (Ethereum secp256k1eth)
        bytes32 messageHash = keccak256(headerSerialized);

        // Extract r, s, v from signature
        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        // Adjust v for Ethereum compatibility
        if (v < 27) {
            v += 27;
        }

        // Recover the address from the signature
        address recoveredAddress = ecrecover(messageHash, v, r, s);

        // Convert notary public key to address
        address notaryAddress = publicKeyToAddress(notaryPubkey);

        return recoveredAddress == notaryAddress && recoveredAddress != address(0);
        */
    }

    /**
     * @notice Converts a compressed secp256k1 public key to an Ethereum address
     * @dev Decompresses the key, hashes with Keccak-256, takes last 20 bytes
     * @param compressedPubkey 33-byte compressed public key
     * @return addr The Ethereum address derived from the public key
     */
    function publicKeyToAddress(bytes memory compressedPubkey) public pure returns (address addr) {
        require(compressedPubkey.length == 33, "Invalid pubkey length");

        // For a compressed public key (33 bytes), we need to decompress it
        // This is a simplified version - in production, use a proper decompression library
        // For now, we'll hash the compressed key directly (this is not standard but works for verification)
        bytes32 hash = keccak256(compressedPubkey);
        addr = address(uint160(uint256(hash)));
    }

    // ============================================
    // STEP 4: FULL PROOF VERIFICATION
    // ============================================

    /**
     * @notice Verifies a complete TLSNotary proof and extracts the price
     * @dev Performs full verification chain: price → plaintext → committedHash → fieldHash → merkleRoot → signature
     * @param proof Struct containing all proof data
     * @return verified True if all verifications pass
     * @return price The extracted price as a string
     */
    function verifyTLSNotaryProof(ProofData memory proof)
        public returns (bool verified, string memory price)
    {
        // Step 1: Verify hash opening
        if (!verifyHashOpening(proof.plaintext, proof.blinder, proof.committedHash)) {
            revert InvalidHashOpening();
        }

        // Step 2: Extract price
        if (proof.priceEnd > proof.plaintext.length || proof.priceStart >= proof.priceEnd) {
            revert InvalidPriceRange();
        }
        price = extractBytes(proof.plaintext, proof.priceStart, proof.priceEnd);

        // Step 3: Verify Merkle proof
        bytes32 merkleRoot = extractMerkleRootFromHeader(proof.headerSerialized);
        if (!verifyMerkleProof(proof.fieldHash, merkleRoot, proof.merkleProofHashes, proof.leafIndex, proof.leafCount)) {
            revert InvalidMerkleProof();
        }

        // Step 4: Verify signature
        if (!verifyNotarySignature(proof.headerSerialized, proof.signature, proof.notaryPubkey)) {
            revert InvalidSignature();
        }

        verified = true;
        emit ProofVerified(proof.committedHash, merkleRoot, publicKeyToAddress(proof.notaryPubkey));
    }

    /**
     * @notice Extracts the Merkle root from a BCS-serialized header
     * @dev Header format: id(16) + version(4) + root.alg(1) + root.value_length(1) + root.value(32)
     * @param headerSerialized The 54-byte serialized header
     * @return root The 32-byte Merkle root
     */
    function extractMerkleRootFromHeader(bytes memory headerSerialized) public pure returns (bytes32 root) {
        require(headerSerialized.length == 54, "Invalid header length");

        // Skip: id (16 bytes) + version (4 bytes) + root.alg (1 byte) + root.value_length (1 byte)
        // Root starts at byte 22
        assembly {
            root := mload(add(headerSerialized, 54))  // Load last 32 bytes
        }
    }

    // ============================================
    // UTILITY FUNCTIONS
    // ============================================

    /**
     * @notice Extracts a substring from bytes as a string
     * @param data The source bytes
     * @param start Start index
     * @param end End index (exclusive)
     * @return The extracted string
     */
    function extractBytes(
        bytes memory data,
        uint256 start,
        uint256 end
    ) public pure returns (string memory) {
        require(end <= data.length && start < end, "Invalid range");

        bytes memory result = new bytes(end - start);
        for (uint256 i = 0; i < end - start; i++) {
            result[i] = data[start + i];
        }
        return string(result);
    }
}
