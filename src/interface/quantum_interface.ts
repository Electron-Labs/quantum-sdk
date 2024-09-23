import { CircuitRegistrationStatus } from "../enum/circuit_registration_status";
import { ProofType } from "../enum/proof_type";
import { Keccak256Hash } from "../types/keccak256_hash";
import { ProofData } from "../types/proof_status";
import { GetProofDataResponse } from "../types/quantum-response/get_proof_data_response";
import { GetProtocolProofResponse } from "../types/quantum-response/get_protocol_proof_response";
import { IsCircuitResgisteredResponse } from "../types/quantum-response/is_circuit_registered_response";
import { RegisterCircuitResponse } from "../types/quantum-response/register_circuit_resposne";
import { SubmitProofResponse } from "../types/quantum-response/submit_proof_response";

export default interface QuantumInterface {
    checkServerConnection(): Promise<boolean>;
    
    registerGnarkGroth16Circuit(vkeyPath: string, proofType: ProofType): Promise<RegisterCircuitResponse>;
    registerSnarkJSGroth16Circuit(vkeyPath: string, proofType: ProofType): Promise<RegisterCircuitResponse>;
    registerGnarkPlonkCircuit(vkeyPath: string, proofType: ProofType): Promise<RegisterCircuitResponse>;
    registerHalo2PlonkCircuit(sg2BinFilePath: string, protocolBinFilePath: string): Promise<RegisterCircuitResponse>;
    
    isCircuitRegistered(circuitHash: string): Promise<IsCircuitResgisteredResponse>
    
    submitGnarkGroth16Proof(proofPath: string, pisPath: string, circuitHash: string): Promise<SubmitProofResponse>;  
    submitSnarkJSGroth16Proof(proofPath: string, pisPath: string, circuitHash: string): Promise<SubmitProofResponse>;  
    submitGnarkPlonkProof(proofPath: string, pisPath: string, circuitHash: string): Promise<SubmitProofResponse>;  
    submitHalo2PlonkProof(proofPath: string, pisPath: string, circuitHash: string): Promise<SubmitProofResponse>;  

    getProofData(proofHash: string): Promise<GetProofDataResponse>;
    getProtocolProof(proofHash: string): Promise<GetProtocolProofResponse>
}