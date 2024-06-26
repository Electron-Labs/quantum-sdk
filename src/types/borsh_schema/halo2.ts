import { borshSerialize } from "../../utils/borsh";

const halo2VkeySchema = {struct: {
    protocol_bytes: {array: {type: 'u8'}},
    sg2_bytes: {array: {type: 'u8'}},
    proof_bytes: {array: {type: 'u8'}},
    instance_bytes: {array: {type: 'u8'}}
}}

const halo2ProofSchema = {struct: { 
    proof_bytes: {array: {type: 'u8'}}
    }
}
const halo2PisSchema = {array: {type: 'u8'}}

export function getHaloVKeySchema() {
    return halo2VkeySchema;
}

export function getHalo2ProofSchema() {
    return halo2ProofSchema;
}

export function getHalo2PubInputSchema() {
    return halo2PisSchema
}

export function serializeHaloProof(proof: any) {
    return borshSerialize(getHalo2ProofSchema(), proof);
}