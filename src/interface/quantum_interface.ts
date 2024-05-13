import { ProofType } from "../enum/proof_type";
import { Keccak256Hash } from "../types/keccak256_hash";
import { ProofStatus } from "../types/proof_status";

export default interface QuantumInterface {
    checkServerConnection(): boolean;
    registerCircuit(vkeyPath: string, cdPath: string, proofType: ProofType): Keccak256Hash;
    submitProof(proofPath: string, pisPath: string, circuitId: Keccak256Hash): Keccak256Hash;  
    getProofData(proofId: Keccak256Hash): ProofStatus;
}