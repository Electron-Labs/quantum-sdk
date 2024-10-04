import { borshSerialize } from "../../utils/borsh";

const plonky2VkeySchema = {struct: {
    common_bytes: {array: {type: 'u8'}},
    verifier_only_bytes: {array: {type: 'u8'}},
}}

const plonky2ProofSchema = {struct: { 
    proof_bytes: {array: {type: 'u8'}}
    }
}
const plonky2PisSchema = {array: {type: 'string'}};

export function getPlonky2VKeySchema() {
    return plonky2VkeySchema;
}

export function getPlonky2ProofSchema() {
    return plonky2ProofSchema;
}

export function getPlonky2PubInputSchema() {
    return plonky2PisSchema
}

export function serializePlonk2Proof(proof: any) {
    return borshSerialize(getPlonky2ProofSchema(), proof);
}