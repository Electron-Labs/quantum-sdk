import { borshSerialize } from "../../utils/borsh";
import { fq, fq2, fq_2 } from "./gnark";

const gnarkPlonkVKey = {
  struct: {
    Size: 'u64',
    SizeInv: 'string',
    Generator: 'string',
    NbPublicVariables: 'u64',
    Kzg: {
      struct: {
        G2: { array: { type: fq2 } },
        G1: fq
      }
    },
    CosetShift: 'u64',
    S: { array: { type: fq } },
    Ql: fq,
    Qr: fq,
    Qm: fq,
    Qo: fq,
    Qk: fq,
    Qcp: { array: { type: fq } },
    CommitmentConstraintIndexes: { array: { type: 'u64' } }
  }
}

const gnarkPlonkSolidityProof = {struct: {
  ProofBytes: { array: { type: 'u8' } }
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
