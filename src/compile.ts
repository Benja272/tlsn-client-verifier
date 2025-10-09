import { Barretenberg, deflattenFields, RawBuffer, splitHonkProof, UltraHonkBackend } from '@aztec/bb.js';
import { Noir } from '@noir-lang/noir_js';
import verifierCircuit from '../circuits/verifier/target/verifier.json' with { type: 'json' };

const noir = new Noir(verifierCircuit);
const backend = new UltraHonkBackend(verifierCircuit.bytecode, { threads: 4 }, { recursive: false });

console.log('Generating Witness... ⏳');

const { witness: verifierWitness } = await noir.execute({x:1, y:2});
console.log(`Verifier witness size: ${verifierWitness.length}`);

console.log('Generating verifierProof... ⏳');
const verifierProof = await backend.generateProof(verifierWitness);
console.log('Generated verifierProof... ✅');
console.log(`Verifier proof bytes length: ${verifierProof.proof.length}`);

console.log('Verifying verifierProof... ⌛');
const verifierIsValid = await backend.verifyProof(verifierProof);
console.log(`VerifierProof is ${verifierIsValid ? 'valid' : 'invalid'}... ✅`);