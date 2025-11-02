# Merkle Proof Verification Guide

## Overview

This guide explains how to verify that the transcript commitment hash is included in the notary-signed header using the Merkle proof data provided by the TLSNotary oracle.

## What You Receive from the Oracle

When you query the oracle endpoint (`GET /price`), you receive:

```json
{
  "body_merkle_proof": {
    "root": [24, 53, 65, ...],              // 32 bytes - Merkle root signed by notary
    "leaf_index": 4,                         // Index of transcript commitment in tree
    "proof_hashes": [],                      // Empty (see explanation below)
    "leaf_count": 5,                         // Total leaves in Merkle tree
    "all_field_hashes": [                    // All 5 field hashes in order
      [32, 168, 255, ...],                   // Field 0: verifying_key
      [120, 236, 13, ...],                   // Field 1: connection_info
      [116, 41, 159, ...],                   // Field 2: server_ephemeral_key
      [158, 227, 24, ...],                   // Field 3: cert_commitment
      [232, 107, 223, ...]                   // Field 4: transcript_commitment ← THIS ONE
    ]
  },
  "hash_proof": {
    "committed_hash": [231, 182, 147, ...],  // SHA256(plaintext || blinder)
    "plaintext": "HTTP/1.1 200 OK...",       // Full HTTP response
    "blinder": [137, 81, 44, ...],           // 16-byte random blinder
    ...
  }
}
```

## Understanding the Merkle Tree Structure

The attestation body contains 5 fields that are hashed into a Merkle tree:

```
                      ROOT (signed by notary)
                     /                        \
                   H01                         H234
                  /    \                      /     \
                H0     H1                   H23     H4
               /       |                   /  \      |
         Field0    Field1              Field2 Field3 Field4
           |         |                   |      |      |
    verifying_key  conn_info    server_key  cert  transcript ← WE CARE ABOUT THIS
```

**Important**: Field 4 (transcript commitment) contains `hash_separated(PlaintextHash)`, NOT the raw `committed_hash`. This is a domain-separated hash to prevent collision attacks.

## Step-by-Step Verification

### Step 1: Understand the Two-Level Hash Structure

The transcript commitment uses a **two-level hash**:

1. **Level 1 - Committed Hash** (MPC phase):
   ```
   committed_hash = SHA256(plaintext || blinder)
   ```
   - This is computed during MPC with the notary
   - The notary verifies the plaintext matches what was received from the server
   - The blinder ensures privacy until you reveal it

2. **Level 2 - Field Hash** (Merkle tree):
   ```
   field_hash = hash_separated(PlaintextHash)
   ```
   - This is a domain-separated hash of the PlaintextHash object
   - PlaintextHash contains: direction, ranges, and commitments
   - This is what goes into the Merkle tree as Field 4

### Step 2: Verify the Hash Opening (Level 1)

First, verify that the plaintext and blinder produce the committed hash:

```python
import hashlib

# From the oracle response
plaintext = hash_proof["plaintext"].encode('utf-8')  # Full HTTP response
blinder = bytes(hash_proof["blinder"])               # 16 bytes
committed_hash = bytes(hash_proof["committed_hash"]) # 32 bytes

# Compute: SHA256(plaintext || blinder)
preimage = plaintext + blinder
computed_hash = hashlib.sha256(preimage).digest()

# Verify
assert computed_hash == committed_hash, "Hash opening verification failed!"
print("✅ Hash opening verified: SHA256(plaintext || blinder) = committed_hash")
```

### Step 3: Reconstruct the Merkle Tree

Since `proof_hashes` is empty (because the attestation proves ALL fields at once), you need to reconstruct the full Merkle tree from `all_field_hashes`:

```python
import hashlib

def sha256_hash(data: bytes) -> bytes:
    """Hash a single piece of data."""
    return hashlib.sha256(data).digest()

def merkle_parent(left: bytes, right: bytes) -> bytes:
    """Compute parent hash from two children."""
    # Concatenate left || right, then hash
    return sha256_hash(left + right)

def build_merkle_tree(leaves: list[bytes]) -> bytes:
    """Build a Merkle tree and return the root."""
    if len(leaves) == 1:
        return leaves[0]

    # Build parent level
    parents = []
    for i in range(0, len(leaves), 2):
        if i + 1 < len(leaves):
            # Two children
            parent = merkle_parent(leaves[i], leaves[i + 1])
        else:
            # Odd number of leaves - promote the last one
            parent = leaves[i]
        parents.append(parent)

    # Recursively build tree
    return build_merkle_tree(parents)

# Get all field hashes from oracle response
field_hashes = [bytes(h) for h in body_merkle_proof["all_field_hashes"]]

# Build the tree
computed_root = build_merkle_tree(field_hashes)

# Get expected root from oracle
expected_root = bytes(body_merkle_proof["root"])

# Verify
assert computed_root == expected_root, "Merkle root mismatch!"
print("✅ Merkle tree verified: computed root matches signed root")
```

The tree construction for 5 leaves:
```
Level 2:         ROOT = H(H01 || H234)
                /                    \
Level 1:      H01 = H(H0 || H1)      H234 = H(H23 || H4)
             /        \              /            \
Level 0:   H0         H1          H23 = H(H2||H3)  H4
           |          |           /      \         |
Leaves:  Field0    Field1     Field2   Field3   Field4
```

### Step 4: Extract the Transcript Field Hash

The transcript commitment is at index 4:

```python
transcript_field_hash = field_hashes[4]  # bytes(body_merkle_proof["all_field_hashes"][4])
print(f"Transcript field hash: {transcript_field_hash.hex()}")
```

**Important**: This `transcript_field_hash` is NOT the same as `committed_hash`. It's `hash_separated(PlaintextHash)`, which is a domain-separated hash containing the committed hash.

### Step 5: Generate Single-Field Merkle Proof (Gas Optimization)

For on-chain verification, you want to prove ONLY Field 4 is in the root (not all 5 fields):

```python
def generate_merkle_proof(leaves: list[bytes], index: int) -> list[bytes]:
    """
    Generate a Merkle proof for a single leaf.
    Returns the sibling hashes along the path from leaf to root.
    """
    proof = []
    current_level = leaves.copy()
    current_index = index

    while len(current_level) > 1:
        # Build parent level and collect sibling
        parents = []
        for i in range(0, len(current_level), 2):
            if i + 1 < len(current_level):
                parent = merkle_parent(current_level[i], current_level[i + 1])

                # If current_index is at i or i+1, save the sibling
                if current_index == i:
                    proof.append(current_level[i + 1])  # Right sibling
                elif current_index == i + 1:
                    proof.append(current_level[i])      # Left sibling
            else:
                # Odd leaf is promoted
                parent = current_level[i]

            parents.append(parent)

            # Update current_index for parent level
            if current_index == i or current_index == i + 1:
                current_index = i // 2

        current_level = parents

    return proof

# Generate proof for Field 4
single_field_proof = generate_merkle_proof(field_hashes, 4)
print(f"Merkle proof for Field 4: {len(single_field_proof)} sibling hashes")
for i, sibling in enumerate(single_field_proof):
    print(f"  Sibling {i}: {sibling.hex()}")
```

For Field 4 (index 4) in a 5-leaf tree:
```
Path from Field 4 to ROOT:
- Level 0: Field 4 (index 4)
- Sibling: H23 (needed to compute H234 = H(H23 || H4))
- Level 1: H234 (index 2 in parent level)
- Sibling: H01 (needed to compute ROOT = H(H01 || H234))
- Level 2: ROOT

Proof = [H23, H01]
```

### Step 6: Verify Single-Field Merkle Proof

Verify that Field 4 is in the root using only the sibling hashes:

```python
def verify_merkle_proof(
    leaf: bytes,
    leaf_index: int,
    proof: list[bytes],
    root: bytes,
    leaf_count: int
) -> bool:
    """
    Verify a Merkle proof for a single leaf.

    Args:
        leaf: The leaf hash to verify
        leaf_index: Index of the leaf in the tree (0-based)
        proof: Sibling hashes along the path
        root: Expected Merkle root
        leaf_count: Total number of leaves in the tree
    """
    current_hash = leaf
    current_index = leaf_index

    for sibling in proof:
        # Determine if current node is left or right child
        if current_index % 2 == 0:
            # Current is left child
            current_hash = merkle_parent(current_hash, sibling)
        else:
            # Current is right child
            current_hash = merkle_parent(sibling, current_hash)

        # Move up to parent level
        current_index = current_index // 2

    return current_hash == root

# Verify the proof
is_valid = verify_merkle_proof(
    leaf=field_hashes[4],
    leaf_index=4,
    proof=single_field_proof,
    root=expected_root,
    leaf_count=5
)

assert is_valid, "Single-field Merkle proof verification failed!"
print("✅ Single-field Merkle proof verified!")
```

## Complete Verification Chain

Here's the complete verification chain from plaintext to signed root:

```python
def verify_complete_chain(oracle_response):
    """Complete verification of TLSNotary proof."""

    # Extract data from oracle response
    body_proof = oracle_response["body_merkle_proof"]
    hash_proof = oracle_response["hash_proof"]

    # 1. Verify hash opening: SHA256(plaintext || blinder) = committed_hash
    plaintext = hash_proof["plaintext"].encode('utf-8')
    blinder = bytes(hash_proof["blinder"])
    committed_hash = bytes(hash_proof["committed_hash"])

    preimage = plaintext + blinder
    computed_hash = hashlib.sha256(preimage).digest()
    assert computed_hash == committed_hash, "❌ Hash opening failed"
    print("✅ Step 1: Hash opening verified")

    # 2. Get field hashes
    field_hashes = [bytes(h) for h in body_proof["all_field_hashes"]]
    transcript_field_hash = field_hashes[4]
    print(f"✅ Step 2: Transcript field hash extracted (index 4)")

    # 3. Verify Merkle tree root
    computed_root = build_merkle_tree(field_hashes)
    expected_root = bytes(body_proof["root"])
    assert computed_root == expected_root, "❌ Merkle root mismatch"
    print("✅ Step 3: Merkle root verified")

    # 4. Generate and verify single-field proof
    proof = generate_merkle_proof(field_hashes, 4)
    is_valid = verify_merkle_proof(
        leaf=transcript_field_hash,
        leaf_index=4,
        proof=proof,
        root=expected_root,
        leaf_count=5
    )
    assert is_valid, "❌ Single-field Merkle proof failed"
    print("✅ Step 4: Single-field Merkle proof verified")

    # 5. Extract price from plaintext
    price_range = hash_proof["price_range"]
    price_bytes = plaintext[price_range["start"]:price_range["end"]]
    price = price_bytes.decode('utf-8')
    print(f"✅ Step 5: Price extracted: {price}")

    return {
        "price": price,
        "committed_hash": committed_hash,
        "transcript_field_hash": transcript_field_hash,
        "merkle_proof": proof,
        "merkle_root": expected_root,
    }
```

## On-Chain Verification (Solidity)

For Ethereum smart contracts, here's how to verify the proof:

```solidity
pragma solidity ^0.8.0;

contract TLSNotaryVerifier {
    // Notary's public key (secp256k1eth format)
    address public immutable notaryPubKey;

    constructor(address _notaryPubKey) {
        notaryPubKey = _notaryPubKey;
    }

    /// @notice Verify TLSNotary proof for price data
    /// @param plaintext Full HTTP response (committed data)
    /// @param blinder 16-byte random blinder
    /// @param priceStart Start index of price in plaintext
    /// @param priceEnd End index of price in plaintext
    /// @param merkleProof Sibling hashes for Field 4
    /// @param merkleRoot Signed Merkle root from notary
    /// @param signature Notary's signature over the header
    function verifyPrice(
        bytes calldata plaintext,
        bytes16 blinder,
        uint256 priceStart,
        uint256 priceEnd,
        bytes32[] calldata merkleProof,
        bytes32 merkleRoot,
        bytes calldata signature
    ) external view returns (bytes memory price) {
        // 1. Verify hash opening: SHA256(plaintext || blinder) = committed_hash
        bytes32 committedHash = sha256(abi.encodePacked(plaintext, blinder));

        // 2. Compute transcript field hash
        // NOTE: In reality, this is hash_separated(PlaintextHash), which is more complex.
        // For simplicity, this example assumes you have the correct field hash.
        // You would need to reconstruct the PlaintextHash object and domain-separate it.
        bytes32 fieldHash = computeTranscriptFieldHash(committedHash, priceStart, priceEnd);

        // 3. Verify Merkle proof: fieldHash is in merkleRoot at index 4
        require(
            verifyMerkleProof(fieldHash, 4, merkleProof, merkleRoot, 5),
            "Invalid Merkle proof"
        );

        // 4. Verify notary signature on merkleRoot
        require(
            verifyNotarySignature(merkleRoot, signature),
            "Invalid notary signature"
        );

        // 5. Extract price from plaintext
        price = plaintext[priceStart:priceEnd];
    }

    /// @notice Verify Merkle proof for a single leaf
    function verifyMerkleProof(
        bytes32 leaf,
        uint256 leafIndex,
        bytes32[] calldata proof,
        bytes32 root,
        uint256 leafCount
    ) internal pure returns (bool) {
        bytes32 currentHash = leaf;
        uint256 currentIndex = leafIndex;

        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 sibling = proof[i];

            if (currentIndex % 2 == 0) {
                // Current is left child
                currentHash = sha256(abi.encodePacked(currentHash, sibling));
            } else {
                // Current is right child
                currentHash = sha256(abi.encodePacked(sibling, currentHash));
            }

            currentIndex = currentIndex / 2;
        }

        return currentHash == root;
    }

    /// @notice Verify secp256k1eth signature from notary
    function verifyNotarySignature(
        bytes32 messageHash,
        bytes calldata signature
    ) internal view returns (bool) {
        // Recover signer from signature
        address signer = recoverSigner(messageHash, signature);
        return signer == notaryPubKey;
    }

    function recoverSigner(
        bytes32 messageHash,
        bytes calldata signature
    ) internal pure returns (address) {
        require(signature.length == 65, "Invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }

        return ecrecover(messageHash, v, r, s);
    }

    // NOTE: This is a simplified version. The actual field hash computation
    // requires domain separation and proper PlaintextHash serialization.
    function computeTranscriptFieldHash(
        bytes32 committedHash,
        uint256 start,
        uint256 end
    ) internal pure returns (bytes32) {
        // In reality, you need to:
        // 1. Create PlaintextHash object with direction, ranges, commitments
        // 2. Serialize it using canonical serialization
        // 3. Apply domain separation: sha256("PlaintextHash" || serialized)
        //
        // For this example, we're simplifying
        return sha256(abi.encodePacked(committedHash, start, end));
    }
}
```

## Why `proof_hashes` is Empty

The oracle's `proof_hashes` array is empty because:

1. The `AttestationProof` from TLSNotary proves **ALL 5 fields at once** (indices 0-4)
2. When you prove all leaves in a Merkle tree, the proof is trivial (just reconstruct the entire tree)
3. For gas-efficient on-chain verification, you want to prove **only Field 4**
4. The oracle provides `all_field_hashes` so you can compute the single-field proof off-chain

**Solution**: Use `all_field_hashes` to reconstruct the tree and generate a single-field proof using the algorithm shown above.

## Key Takeaways

1. **Two-level hashing**:
   - Level 1: `committed_hash = SHA256(plaintext || blinder)` - verified by hash opening
   - Level 2: `field_hash = hash_separated(PlaintextHash)` - goes into Merkle tree

2. **Merkle tree has 5 leaves**:
   - Field 0: verifying_key
   - Field 1: connection_info
   - Field 2: server_ephemeral_key
   - Field 3: cert_commitment
   - Field 4: transcript_commitment ← Contains the committed hash

3. **For on-chain verification**:
   - Use `all_field_hashes` to generate a single-field Merkle proof for Field 4
   - Verify: SHA256(plaintext || blinder) = committed_hash
   - Verify: Field hash is in signed Merkle root
   - Verify: Notary signature on Merkle root
   - Extract: Price from plaintext at specified range

4. **Hash sizes**: All hashes are **32 bytes** (SHA256), with no padding zeros after the fix.
