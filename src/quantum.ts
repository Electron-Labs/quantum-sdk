import { ProofType } from "./enum/proof_type";
import QuantumInterface from "./interface/quantum_interface";
import { Keccak256Hash } from "./types/keccak256_hash";
import { ProofStatus } from "./types/proof_status";

export class Quantum implements QuantumInterface {
    private rpcEndPoint: string;
    constructor(rpcEndPoint: string) {
        this.rpcEndPoint = rpcEndPoint;
    }

    public getRpcEndPoint() {
        return this.rpcEndPoint;
    }

    checkServerConnection(): boolean {
        throw new Error("Method not implemented.");
    }
    registerCircuit(vkeyPath: string, cdPath: string, proofType: ProofType): Keccak256Hash {
        throw new Error("Method not implemented.");
    }
    submitProof(proofPath: string, pisPath: string, circuitId: Keccak256Hash): Keccak256Hash {
        throw new Error("Method not implemented.");
    }
    getProofData(proofId: Keccak256Hash): ProofStatus {
        throw new Error("Method not implemented.");
    }
    
}