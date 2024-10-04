import { borshSerialize } from "../../utils/borsh";

const halo2PoseidonVkeySchema = {struct: {
    protocol_bytes: {array: {type: 'u8'}},
    sg2_bytes: {array: {type: 'u8'}},
}}

const halo2PoseidonProofSchema = {struct: { 
    proof_bytes: {array: {type: 'u8'}}
    }
}
const halo2PoseidonPisSchema = {array: {type: 'u8'}}

export function getHalo2PoseidonVKeySchema() {
    return halo2PoseidonVkeySchema;
}

export function getHalo2PoseidonProofSchema() {
    return halo2PoseidonProofSchema;
}

export function getHalo2PoseidonPubInputSchema() {
    return halo2PoseidonPisSchema
}

export function serializeHalo2PoseidonProof(proof: any) {
    return borshSerialize(getHalo2PoseidonProofSchema(), proof);
}