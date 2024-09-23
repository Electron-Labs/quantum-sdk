import { borshSerialize } from "../../utils/borsh";

export const fq = {struct : {
    X: 'string',
    Y: 'string'
}}

export const fq_2 = {struct : {
    A0: 'string',
    A1: 'string'
}}

export const fq2 = { struct : {
    X : fq_2,
    Y: fq_2
}}

const gnarkVkey = {struct : {
    vkey_bytes: {array: {type: 'u8'}}
}}

const gnarkPubInputs = {array: {type: 'string'}};

const gnarkProof = {struct : {
    proof_bytes: {array: {type: 'u8'}}
}}

export function getGnarkVKeySchema() {
    return gnarkVkey;
}

export function getGnarkPubInputsSchema(){
    return gnarkPubInputs;
}

export function getGnarkProofSchema() {
    return gnarkProof;
}

export function serializeGnarkProof(proof: any) {
    return borshSerialize(getGnarkProofSchema(), proof);
}
