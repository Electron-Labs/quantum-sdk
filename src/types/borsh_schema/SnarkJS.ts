import { borshSerialize } from "../../utils/borsh";

const nestedArrayOfStringType = { array: { type : { array : {type: 'string'}}}}

const snarkJSVkey = {struct : {
    protocol : 'string',
    curve: 'string',
    nPublic: 'u32',
    vk_alpha_1 : { array: { type: 'string'}},
    vk_beta_2 : nestedArrayOfStringType,
    vk_gamma_2: nestedArrayOfStringType,
    vk_delta_2: nestedArrayOfStringType,
    vk_alphabeta_12: { array : {type: nestedArrayOfStringType } },
    IC: nestedArrayOfStringType
}}

const snarkJSProof = {struct: {
    pi_a: {array: {type: 'string'}},
    pi_b: nestedArrayOfStringType,
    pi_c: {array: {type: 'string'}},
    protocol: 'string',
    curve: 'string'
}}

const snarkJSPubInput = {array: {type: 'string'}};

export function getSnarkJSProofSchema() {
    return snarkJSProof;
}

export function getSnarkJSPubInputSchema() {
    return snarkJSPubInput;
}

export function getSnarkJSVkeySchema() {
    return snarkJSVkey;
}

export function serializeSnarkProof(proof: any) {
    return borshSerialize(getSnarkJSProofSchema(), proof);
}