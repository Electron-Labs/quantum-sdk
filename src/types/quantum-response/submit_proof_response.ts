import { Keccak256Hash } from "../keccak256_hash";

export class SubmitProofResponse {
    proofHash: Keccak256Hash;
    constructor(proofHash: Keccak256Hash) {
        this.proofHash = proofHash
    } 
}