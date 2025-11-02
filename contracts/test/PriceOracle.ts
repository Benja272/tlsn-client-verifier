import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { network } from "hardhat";
import { parseEther, toHex, bytesToHex, hexToBytes } from "viem";

describe("PriceOracle with TLSNotary Verification", async function () {
  const { viem } = await network.connect();
  const publicClient = await viem.getPublicClient();

  it("Should deploy TLSNotaryVerifier and PriceOracle contracts", async function () {
    // Deploy the TLSNotaryVerifier contract
    const verifier = await viem.deployContract("TLSNotaryVerifier");

    // Trusted notary pubkey from test data
    const trustedNotaryPubkey = "0x036888fb5e383a4d72c2335186fd5858e7ae743ab4bf8e071b06e7";

    // Deploy the PriceOracle contract
    const priceOracle = await viem.deployContract("PriceOracle", [
      verifier.address,
      trustedNotaryPubkey,
    ]);

    // Verify the verifier address is set correctly
    const verifierAddress = await priceOracle.read.verifier() as `0x${string}`;
    assert.equal(verifierAddress.toLowerCase(), verifier.address.toLowerCase());

    // Verify the trusted notary is set correctly
    const trustedNotary = await priceOracle.read.trustedNotaryPubkey() as `0x${string}`;
    assert.equal(trustedNotary.toLowerCase(), trustedNotaryPubkey.toLowerCase());

    console.log("✅ Contracts deployed successfully");
    console.log("   TLSNotaryVerifier:", verifier.address);
    console.log("   PriceOracle:", priceOracle.address);
  });

  it("Should verify hash opening with SHA-256", async function () {
    const verifier = await viem.deployContract("TLSNotaryVerifier");

    // Load test data
    const proofDataPath = join(process.cwd(), "test", "fixtures", "proof_data.json");
    const proofDataContent = await readFile(proofDataPath, "utf-8");
    const proofData = JSON.parse(proofDataContent);

    // Test hash opening
    const plaintext = proofData.plaintextHex as `0x${string}`;
    const blinder = proofData.blinderHex as `0x${string}`;
    const committedHash = proofData.committedHash as `0x${string}`;

    console.log("📝 Testing hash opening...");
    console.log("   Plaintext:", proofData.plaintext);
    console.log("   Blinder:", blinder);
    console.log("   Committed Hash:", committedHash);

    const isValid = await verifier.read.verifyHashOpening([
      plaintext,
      blinder,
      committedHash,
    ]);

    assert.equal(isValid, true, "Hash opening should be valid");
    console.log("✅ Hash opening verified successfully");
  });

  it("Should verify Merkle proof with SHA-256", async function () {
    const verifier = await viem.deployContract("TLSNotaryVerifier");

    // Load test data
    const proofDataPath = join(process.cwd(), "test", "fixtures", "proof_data.json");
    const proofDataContent = await readFile(proofDataPath, "utf-8");
    const proofData = JSON.parse(proofDataContent);

    // The Merkle tree contains field hashes as leaves, not committed hashes
    const leaf = proofData.fieldHash as `0x${string}`;
    const root = proofData.merkleRoot as `0x${string}`;
    const proofHashes = proofData.merkleProofHashes as `0x${string}`[];
    const leafIndex = BigInt(proofData.leafIndex);
    const leafCount = BigInt(proofData.leafCount);

    console.log("📝 Testing Merkle proof...");
    console.log("   Leaf (fieldHash):", leaf);
    console.log("   Root:", root);
    console.log("   Leaf Index:", leafIndex.toString());
    console.log("   Leaf Count:", leafCount.toString());
    console.log("   Proof Hashes:", proofHashes.length);

    const isValid = await verifier.read.verifyMerkleProof([
      leaf,
      root,
      proofHashes,
      leafIndex,
      leafCount,
    ]);

    assert.equal(isValid, true, "Merkle proof should be valid");
    console.log("✅ Merkle proof verified successfully");
  });

  it("Should verify notary signature with SHA-256", async function () {
    const verifier = await viem.deployContract("TLSNotaryVerifier");

    // Load test data
    const proofDataPath = join(process.cwd(), "test", "fixtures", "proof_data.json");
    const proofDataContent = await readFile(proofDataPath, "utf-8");
    const proofData = JSON.parse(proofDataContent);

    const headerSerialized = proofData.headerSerializedHex as `0x${string}`;
    const signature = proofData.signatureHex as `0x${string}`;
    const notaryPubkey = proofData.notaryPubkeyHex as `0x${string}`;

    console.log("📝 Testing signature verification...");
    console.log("   Header length:", hexToBytes(headerSerialized).length);
    console.log("   Signature length:", hexToBytes(signature).length);
    console.log("   Notary pubkey:", notaryPubkey);

    const isValid = await verifier.read.verifyNotarySignature([
      headerSerialized,
      signature,
      notaryPubkey,
    ]);

    assert.equal(isValid, true, "Signature should be valid");
    console.log("✅ Signature verified successfully");
  });

  it("Should verify full TLSNotary proof and extract price", async function () {
    const verifier = await viem.deployContract("TLSNotaryVerifier");

    // Load test data
    const proofDataPath = join(process.cwd(), "test", "fixtures", "proof_data.json");
    const proofDataContent = await readFile(proofDataPath, "utf-8");
    const proofData = JSON.parse(proofDataContent);

    console.log("📝 Testing full TLSNotary proof verification...");
    console.log("   Symbol:", proofData.symbol);
    console.log("   Expected Price:", proofData.price);

    // Prepare ProofData struct
    const proofDataStruct = {
      plaintext: proofData.plaintextHex,
      blinder: proofData.blinderHex,
      committedHash: proofData.committedHash,
      fieldHash: proofData.fieldHash,
      merkleProofHashes: proofData.merkleProofHashes,
      leafIndex: BigInt(proofData.leafIndex),
      leafCount: BigInt(proofData.leafCount),
      headerSerialized: proofData.headerSerializedHex,
      signature: proofData.signatureHex,
      notaryPubkey: proofData.notaryPubkeyHex,
      priceStart: BigInt(proofData.priceStart),
      priceEnd: BigInt(proofData.priceEnd),
    };

    const result = await verifier.read.verifyTLSNotaryProof([proofDataStruct]);

    const [verified, price] = result as [boolean, string];

    assert.equal(verified, true, "Full proof should be valid");
    assert.equal(price, proofData.price, `Price should be ${proofData.price}`);

    console.log("✅ Full proof verified successfully");
    console.log("   Verified:", verified);
    console.log("   Extracted Price:", price);
  });

  it("Should update price in PriceOracle with verified proof", async function () {
    const verifier = await viem.deployContract("TLSNotaryVerifier");

    // Use the notary pubkey from the test data
    const trustedNotaryPubkey = "0x03192ae7254d969ba11765cfc15ac0a1e8c0323f8a6b7bc70c33ed4f15a796d4e2";
    const priceOracle = await viem.deployContract("PriceOracle", [
      verifier.address,
      trustedNotaryPubkey,
    ]);

    // Load test data
    const proofDataPath = join(process.cwd(), "test", "fixtures", "proof_data.json");
    const proofDataContent = await readFile(proofDataPath, "utf-8");
    const proofData = JSON.parse(proofDataContent);

    console.log("📝 Testing price update in PriceOracle...");
    console.log("   Symbol:", proofData.symbol);
    console.log("   Price:", proofData.price);

    // Prepare ProofParams struct
    const proofParams = {
      plaintext: proofData.plaintextHex,
      blinder: proofData.blinderHex,
      committedHash: proofData.committedHash,
      fieldHash: proofData.fieldHash,
      merkleProofHashes: proofData.merkleProofHashes,
      leafIndex: BigInt(proofData.leafIndex),
      leafCount: BigInt(proofData.leafCount),
      headerSerialized: proofData.headerSerializedHex,
      signature: proofData.signatureHex,
      notaryPubkey: proofData.notaryPubkeyHex,
      priceStart: BigInt(proofData.priceStart),
      priceEnd: BigInt(proofData.priceEnd),
    };

    // Call updatePrice
    const tx = await priceOracle.write.updatePrice([
      proofData.symbol,
      proofParams,
    ]);

    const receipt = await publicClient.waitForTransactionReceipt({ hash: tx });
    assert.equal(receipt.status, "success", "Transaction should succeed");

    console.log("✅ Price updated successfully");
    console.log("   Transaction hash:", tx);

    // Verify the price was stored
    const storedPrice = await priceOracle.read.getLatestPrice([proofData.symbol]);
    assert.equal(storedPrice.price, proofData.price, "Stored price should match");
    assert.equal(storedPrice.exists, true, "Price should exist");

    console.log("✅ Price stored correctly");
    console.log("   Stored Price:", storedPrice.price);
    console.log("   Timestamp:", storedPrice.timestamp.toString());
    console.log("   Block Number:", storedPrice.blockNumber.toString());
  });

  it("Should reject replay attacks", async function () {
    const verifier = await viem.deployContract("TLSNotaryVerifier");

    // Use the notary pubkey from the test data
    const trustedNotaryPubkey = "0x03192ae7254d969ba11765cfc15ac0a1e8c0323f8a6b7bc70c33ed4f15a796d4e2";
    const priceOracle = await viem.deployContract("PriceOracle", [
      verifier.address,
      trustedNotaryPubkey,
    ]);

    // Load test data
    const proofDataPath = join(process.cwd(), "test", "fixtures", "proof_data.json");
    const proofDataContent = await readFile(proofDataPath, "utf-8");
    const proofData = JSON.parse(proofDataContent);

    const proofParams = {
      plaintext: proofData.plaintextHex,
      blinder: proofData.blinderHex,
      committedHash: proofData.committedHash,
      fieldHash: proofData.fieldHash,
      merkleProofHashes: proofData.merkleProofHashes,
      leafIndex: BigInt(proofData.leafIndex),
      leafCount: BigInt(proofData.leafCount),
      headerSerialized: proofData.headerSerializedHex,
      signature: proofData.signatureHex,
      notaryPubkey: proofData.notaryPubkeyHex,
      priceStart: BigInt(proofData.priceStart),
      priceEnd: BigInt(proofData.priceEnd),
    };

    // First update should succeed
    await priceOracle.write.updatePrice([proofData.symbol, proofParams]);

    console.log("📝 Testing replay attack protection...");

    // Second update with same proof should fail
    try {
      await priceOracle.write.updatePrice([proofData.symbol, proofParams]);
      assert.fail("Second update should have been rejected");
    } catch (error: any) {
      assert.ok(error.message.includes("ProofAlreadyUsed") || error.message.includes("revert"));
      console.log("✅ Replay attack rejected successfully");
    }
  });
});
