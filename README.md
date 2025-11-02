# TLSNotary Price Oracle - Smart Contract Verification

On-chain verification of TLSNotary proofs from the Binance oracle. This creates a trustless bridge between off-chain API data and smart contracts.

## Project Structure

This project consists of two repositories:

1. **[TLSNotary Oracle Server](https://github.com/Benja272/tlsn)** - Rust implementation
   - Fetches BTC price from Binance API via TLSNotary
   - Generates cryptographic proofs (hash commitments, Merkle proofs, signatures)
   - Runs notary server and oracle HTTP server

2. **This Repository** - Smart Contract Verification (Solidity + TypeScript)
   - On-chain verification of TLSNotary proofs
   - Price oracle storage with replay protection
   - Integration tests and deployment scripts

## ⚠️ Learning Version

**This is simplified for education.** Signature verification is simplified (always returns true). For production, compute `fieldHash` on-chain or run your own oracle infrastructure.

## What Gets Verified

1. **Hash Opening** (SHA-256): `SHA256(plaintext || blinder) == committedHash`
2. **Merkle Proof** (SHA-256): Proves commitment is in the signed attestation
3. **Signature** (secp256k1): Verifies notary signed the data (simplified)

## Quick Start

### Prerequisites

You need the oracle servers running (see [parent README](../README.md)):

```bash
# Terminal 1: Notary server
NS_NOTARIZATION__SIGNATURE_ALGORITHM=secp256k1eth cargo run --bin notary-server

# Terminal 2: Oracle server
USE_LOCAL_NOTARY=1 cargo run --example binance_oracle_server
```

### Install & Test

```bash
cd contracts
npm install
npm run compile
npm test
```

Expected: 5-7 passing tests including hash opening, Merkle proof, signature verification, price updates, and replay protection.

## End-to-End Example

### 1. Start Local Node

```bash
npx hardhat node
```

### 2. Fetch Oracle Data

In another terminal:

```bash
npm run update-price
```

This fetches current BTC price from oracle and creates `test/fixtures/proof_data.json`.

### 3. Run Complete Example

```bash
npm run example
```

This script:
- ✅ Deploys TLSNotaryVerifier and PriceOracle contracts
- ✅ Submits TLSNotary proof to verify and store price on-chain
- ✅ Queries the verified price
- ✅ Tests replay attack protection

**Output:**
```
✅ SUCCESS! Price verified and stored on-chain:
Symbol: BTCUSDT
Price: 110522.39000000
Block Number: 2
Submitter: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
```

## Architecture

```
Oracle Server (localhost:3000)
    ↓ HTTP
Off-Chain Script (update_price.ts)
    ↓ Prepare proof data
Smart Contract (PriceOracle.sol)
    ├─ TLSNotaryVerifier.verifyTLSNotaryProof()
    │   ├─ verifyHashOpening()
    │   ├─ verifyMerkleProof()
    │   └─ verifyNotarySignature()
    └─ Store verified price on-chain
```

## Project Structure

```
contracts/
├── contracts/
│   ├── TLSNotaryVerifier.sol    # Crypto verification
│   └── PriceOracle.sol           # Price storage
├── test/
│   └── PriceOracle.ts            # Integration tests
├── scripts/
│   ├── update_price.ts           # Fetch from oracle
│   └── example_e2e.ts            # Complete demo
└── ignition/modules/
    └── PriceOracle.ts            # Deployment
```

## Gas Costs

| Operation | Gas Cost |
|-----------|----------|
| Deploy contracts | ~1.3M (one-time) |
| Update price | ~180k |
| Query price | 0 (view) |

## Deployment

### Local

```bash
npm run deploy:local
```

### Testnet (Sepolia)

```bash
npx hardhat keystore set SEPOLIA_PRIVATE_KEY
npx hardhat ignition deploy --network sepolia ignition/modules/PriceOracle.ts
```

### Custom Notary

```bash
npx hardhat ignition deploy \
  --parameters '{"PriceOracleModule":{"trustedNotaryPubkey":"0x03..."}}' \
  ignition/modules/PriceOracle.ts
```

## Common Issues

**"UntrustedNotary" error**: Notary pubkey mismatch. Update contract or regenerate proof data.

**"ProofAlreadyUsed" error**: Trying to replay same proof. Fetch fresh data: `npm run update-price`

**Tests failing**: Ensure oracle is running at `localhost:3000`, then regenerate test data.

## Production Considerations

For production use:

1. **Compute `fieldHash` on-chain** (~50k extra gas) - closes security gap
2. **Run your own infrastructure** - deploy your own notary + oracle
3. **Multi-oracle consensus** - query multiple sources
4. **Deploy on L2** - 10x cheaper gas costs

## Scripts

```bash
npm test              # Run all tests
npm run update-price  # Fetch proof from oracle
npm run example       # Run end-to-end demo
npm run deploy:local  # Deploy to local node
```

## Learn More

### Related Repositories

- **[TLSNotary Oracle Server](https://github.com/Benja272/tlsn)** - Rust implementation of the oracle and notary server
- **[TLSNotary Official](https://github.com/tlsnotary/tlsn)** - Official TLSNotary protocol implementation

### Documentation

- [TLSNotary Documentation](https://docs.tlsnotary.org)
- [TLSNotary Discord](https://discord.gg/9XwESXtcN7)

---

**License**: MIT | **Security**: Educational use only - see production considerations above
