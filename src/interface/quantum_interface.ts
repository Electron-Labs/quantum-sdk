import { ProofType } from "../enum/proof_type";
import { Keccak256Hash } from "../types/keccak256_hash";
import { ProofStatus } from "../types/proof_status";

export default interface QuantumInterface {
    checkServerConnection(): Promise<boolean>;
    registerCircuit(vkeyPath: string, publicInputsCount: number, proofType: ProofType): Promise<Keccak256Hash>;
    submitProof(proofPath: string, pisPath: string, circuitId: Keccak256Hash): Keccak256Hash;  
    getProofData(proofId: Keccak256Hash): ProofStatus;
}