import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("PriceOracleModule", (m) => {
  // Get the trusted notary public key from parameters
  // This should be the 33-byte compressed secp256k1 public key from the TLSNotary oracle
  const trustedNotaryPubkey = m.getParameter(
    "trustedNotaryPubkey",
    "0x028a504a8a96760827924c5ae424f84d1ba775f05583f2c998b8a249b17923f683" // Default from test data
  );

  // Deploy the TLSNotaryVerifier contract
  const tlsNotaryVerifier = m.contract("TLSNotaryVerifier");

  // Deploy the PriceOracle contract with the verifier and trusted notary
  const priceOracle = m.contract("PriceOracle", [
    tlsNotaryVerifier,
    trustedNotaryPubkey,
  ]);

  return { tlsNotaryVerifier, priceOracle };
});
