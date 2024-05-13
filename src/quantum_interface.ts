import { ProofType } from "./enum/proof_type";
import { ProofStatus } from "./proof_status";

export default interface QuantumInterface {
    checkServerConnection(): boolean;
    registerCircuit(vkeyPath: string, cdPath: string, proofType: ProofType): string;
    submitProof(proofPath: string, pisPath: string, circuitId: string): string;  
    getProofData(proofId: string): ProofStatus;
}