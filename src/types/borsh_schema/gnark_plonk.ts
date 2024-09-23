import { borshSerialize } from "../../utils/borsh";
import { fq, fq2, fq_2 } from "./gnark";

const gnarkPlonkVKey = {struct: {
  vkey_bytes: { array: { type: 'u8' } }
}}

const gnarkPlonkSolidityProof = {struct: {
  proof_bytes: { array: { type: 'u8' } }
}}

const gnarkPlonkPubInputs = { array: { type: 'string' } };

export function getGnarkPlonkVKeySchema() {
  return gnarkPlonkVKey;
}

export function getGnarkPlonkPubInputsSchema() {
  return gnarkPlonkPubInputs;
}

export function getGnarkPlonkProofSchema() {
  return gnarkPlonkSolidityProof;
}

export function serializeGnarkPlonkProof(proof: any) {
  return borshSerialize(getGnarkPlonkProofSchema(), proof);
}
