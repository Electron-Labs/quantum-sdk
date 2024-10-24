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
    
    registerGnarkGroth16Circuit(vkeyJsonFilePath: string): Promise<RegisterCircuitResponse>;
    registerSnarkJSGroth16Circuit(vkeyBinFilePath: string): Promise<RegisterCircuitResponse>;
    registerGnarkPlonkCircuit(vkeyBinFilePath: string): Promise<RegisterCircuitResponse>;
    registerHalo2KZGEvmCircuit(sg2JsonFilePath: string, protocolJsonFilePath: string): Promise<RegisterCircuitResponse>;
    registerHalo2KZGCircuit(sg2JsonFilePath: string, protocolJsonFilePath: string): Promise<RegisterCircuitResponse>;
    registerPlonky2Circuit(commonCircuitDataBinFilePath: string, verifierOnlyBinFilePath: string): Promise<RegisterCircuitResponse>;
    registerRisc0Circuit(vkeyJsonPath: string): Promise<RegisterCircuitResponse>;
    registerSp1Circuit(vkeyBinFilePath: string): Promise<RegisterCircuitResponse>;

    isCircuitRegistered(circuitHash: string): Promise<IsCircuitResgisteredResponse>
    
    submitGnarkGroth16Proof(proofBinFilePath: string, pisJsonFilePath: string, circuitHash: string): Promise<SubmitProofResponse>;  
    submitSnarkJSGroth16Proof(proofJsonPath: string, pisJsonFilePath: string, circuitHash: string): Promise<SubmitProofResponse>;  
    submitGnarkPlonkProof(proofBinFilePath: string, pisJsonFilePath: string, circuitHash: string): Promise<SubmitProofResponse>;  
    submitHalo2KZGEvmProof(proofBinFilePath: string, instancesJsonFilepath: string, circuitHash: string): Promise<SubmitProofResponse>; 
    submitHalo2KZGProof(proofBinFilePath: string, instancesJsonFilepath: string, circuitHash: string): Promise<SubmitProofResponse>;
    submitPlonky2Proof(proofBinFilePath: string, circuitHash: string): Promise<SubmitProofResponse>;
    submitRisc0Proof(receiptBinFilePath: string, circuitHash: string): Promise<SubmitProofResponse>;
    submitSp1Proof(proofBinFilePath: string, circuitHash: string): Promise<SubmitProofResponse>;
    
    getProofData(proofHash: string): Promise<GetProofDataResponse>;
    getProtocolProof(proofHash: string): Promise<GetProtocolProofResponse>
}