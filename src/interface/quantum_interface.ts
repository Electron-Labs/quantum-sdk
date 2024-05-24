import { CircuitRegistrationStatus } from "../enum/circuit_registration_status";
import { ProofType } from "../enum/proof_type";
import { Keccak256Hash } from "../types/keccak256_hash";
import { ProofData } from "../types/proof_status";

export default interface QuantumInterface {
    checkServerConnection(): Promise<boolean>;
    registerCircuit(vkeyPath: string, publicInputsCount: number, proofType: ProofType): Promise<Keccak256Hash>;
    isCircuitRegistered(circuitId: string): Promise<CircuitRegistrationStatus>
    submitProof(proofPath: string, pisPath: string, circuitId: string, proofType: ProofType): Promise<Keccak256Hash>;  
    getProofData(proofId: string): Promise<ProofData>;
}