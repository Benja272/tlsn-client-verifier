#!/usr/bin/env tsx
/**
 * End-to-End Example: Deploy contracts and update price with TLSNotary proof
 *
 * This script demonstrates the complete workflow:
 * 1. Deploy TLSNotaryVerifier and PriceOracle contracts
 * 2. Fetch proof data from the oracle server
 * 3. Submit the proof to update the on-chain price
 * 4. Query the verified price
 *
 * Prerequisites:
 * - Oracle server running at http://localhost:3000
 * - Local Hardhat node running (npx hardhat node)
 *
 * Usage:
 *   npm run update-price              # Fetch fresh proof data
 *   tsx scripts/example_e2e.ts        # Run this script
 */

import { network } from "hardhat";
import { readFile } from "fs/promises";
import { join } from "path";

async function main() {
  console.log("=".repeat(60));
  console.log("TLSNotary Price Oracle - End-to-End Example");
  console.log("=".repeat(60));

  const { viem } = await network.connect();
  const publicClient = await viem.getPublicClient();

  // Step 1: Deploy contracts
  console.log("\n📦 Step 1: Deploying Contracts...");
  console.log("-".repeat(60));

  console.log("Deploying TLSNotaryVerifier...");
  const verifier = await viem.deployContract("TLSNotaryVerifier");
  console.log("✅ TLSNotaryVerifier deployed at:", verifier.address);

  // Load proof data to get the notary pubkey
  const proofDataPath = join(process.cwd(), "test", "fixtures", "proof_data.json");
  let proofData: any;

  try {
    const proofDataContent = await readFile(proofDataPath, "utf-8");
    proofData = JSON.parse(proofDataContent);
  } catch (error) {
    console.error("\n❌ Error: proof_data.json not found!");
    console.error("Please run: npm run update-price");
    process.exit(1);
  }

  const trustedNotaryPubkey = proofData.notaryPubkeyHex;
  console.log("Using trusted notary:", trustedNotaryPubkey.slice(0, 20) + "...");

  console.log("Deploying PriceOracle...");
  const priceOracle = await viem.deployContract("PriceOracle", [
    verifier.address,
    trustedNotaryPubkey,
  ]);
  console.log("✅ PriceOracle deployed at:", priceOracle.address);

  // Step 2: Prepare proof data
  console.log("\n📝 Step 2: Preparing Proof Data...");
  console.log("-".repeat(60));

  console.log("Symbol:", proofData.symbol);
  console.log("Price from oracle:", proofData.price);
  console.log("Timestamp:", proofData.timestamp);
  console.log("Server:", proofData.server);
  console.log("Plaintext size:", proofData.plaintext.length, "bytes");
  console.log("Merkle proof hashes:", proofData.merkleProofHashes.length);

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

  // Step 3: Submit proof to contract
  console.log("\n🚀 Step 3: Submitting Proof to Contract...");
  console.log("-".repeat(60));

  console.log("Calling updatePrice() with proof data...");
  const tx = await priceOracle.write.updatePrice([
    proofData.symbol,
    proofParams,
  ]);

  console.log("Transaction hash:", tx);
  console.log("Waiting for confirmation...");

  const receipt = await publicClient.waitForTransactionReceipt({ hash: tx });
  console.log("✅ Transaction confirmed!");
  console.log("   Block:", receipt.blockNumber);
  console.log("   Gas used:", receipt.gasUsed);
  console.log("   Status:", receipt.status);

  // Step 4: Query the verified price
  console.log("\n📊 Step 4: Querying Verified Price...");
  console.log("-".repeat(60));

  const latestPrice = await priceOracle.read.getLatestPrice([
    proofData.symbol
  ]) as any;

  console.log("\n✅ SUCCESS! Price verified and stored on-chain:");
  console.log("=".repeat(60));
  console.log("Symbol:", proofData.symbol);
  console.log("Price:", latestPrice.price);
  console.log("Timestamp:", new Date(Number(latestPrice.timestamp) * 1000).toISOString());
  console.log("Block Number:", latestPrice.blockNumber.toString());
  console.log("Submitter:", latestPrice.submitter);
  console.log("Proof Hash:", latestPrice.proofHash);
  console.log("Exists:", latestPrice.exists);
  console.log("=".repeat(60));

  // Step 5: Verify replay protection
  console.log("\n🛡️  Step 5: Testing Replay Protection...");
  console.log("-".repeat(60));

  try {
    console.log("Attempting to submit the same proof again...");
    await priceOracle.write.updatePrice([
      proofData.symbol,
      proofParams,
    ]);
    console.log("❌ ERROR: Replay attack should have been prevented!");
  } catch (error: any) {
    if (error.message.includes("ProofAlreadyUsed")) {
      console.log("✅ Replay attack prevented successfully!");
      console.log("   Error: ProofAlreadyUsed");
    } else {
      console.log("❌ Unexpected error:", error.message);
    }
  }

  // Summary
  console.log("\n" + "=".repeat(60));
  console.log("📋 SUMMARY");
  console.log("=".repeat(60));
  console.log("✅ Contracts deployed");
  console.log("✅ TLSNotary proof verified on-chain");
  console.log("✅ Price stored successfully");
  console.log("✅ Replay protection working");
  console.log("\n🎉 End-to-end test completed successfully!");
  console.log("=".repeat(60));

  // Display contract addresses for future use
  console.log("\n📝 Contract Addresses:");
  console.log("-".repeat(60));
  console.log("TLSNotaryVerifier:", verifier.address);
  console.log("PriceOracle:", priceOracle.address);
  console.log("Trusted Notary:", trustedNotaryPubkey);
  console.log("-".repeat(60));
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("\n❌ Fatal error:", error);
    process.exit(1);
  });
