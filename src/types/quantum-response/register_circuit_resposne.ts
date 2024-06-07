import { Keccak256Hash } from "../keccak256_hash";

export class RegisterCircuitResponse {
    public circuitHash: Keccak256Hash;
    constructor(circuitHash: Keccak256Hash) {
        this.circuitHash = circuitHash
    } 
}