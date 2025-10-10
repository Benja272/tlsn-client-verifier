import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("OracleModule", (m) => {
  // Deploy the Verifier contract first (UltraHonk verifier generated from Noir)
  const verifier = m.contract("HonkVerifier");

  // Deploy the Oracle contract with the verifier address
  const oracle = m.contract("Oracle", [verifier]);

  return { verifier, oracle };
});
