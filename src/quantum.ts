import { checkServerConnection } from "./api_handler/check_server_connection";
import { getCircuitRegistrationStatus, registerCircuit } from "./api_handler/register_circuit";
import { get_proof_status, getProtocolProof, submitProof } from "./api_handler/submit_proof";
import { CircuitRegistrationStatus, getCircuitRegistrationStatusFromString } from "./enum/circuit_registration_status";
import { ProofType } from "./enum/proof_type";
import QuantumInterface from "./interface/quantum_interface";
import { getPis, getProof, getProofStatusFromResponse, getProtocolProofFromResponse, serializeProof, serializePubInputs, serializeVKey } from "./quantum_helper";
import { IsCircuitRegistered } from "./types/is_circuit_registered";
import { Keccak256Hash } from "./types/keccak256_hash";
import { ProofData } from "./types/proof_status";
import { GetProofDataResponse } from "./types/quantum-response/get_proof_data_response";
import { GetProtocolProofResponse } from "./types/quantum-response/get_protocol_proof_response";
import { IsCircuitResgisteredResponse } from "./types/quantum-response/is_circuit_registered_response";
import { RegisterCircuitResponse } from "./types/quantum-response/register_circuit_resposne";
import { SubmitProofResponse } from "./types/quantum-response/submit_proof_response";
import { checkPathAndReadFile, checkPathAndReadJsonFile } from "./utils/file";
import { ProtocolProof } from "../src/types/protocol_proof";
import { ProtocolInclusionProof } from "../src/types/protocol_inclusion_proof";
import { toLeBytes32 } from "./utils/bytes";

export class Quantum implements QuantumInterface {
    private rpcEndPoint: string;
    private authToken: string;
    constructor(rpcEndPoint: string, authToken: string) {
        this.rpcEndPoint = rpcEndPoint;
        this.authToken = authToken;
    }
    async isCircuitRegistered(circuitHash: string): Promise<IsCircuitResgisteredResponse> {
        const circuit_hash = Keccak256Hash.fromString(circuitHash);
        const isCircuitRegistrationResponse = await getCircuitRegistrationStatus(circuitHash, this.rpcEndPoint, this.authToken);
        const isCircuitRegistered = new IsCircuitRegistered({
            circuitRegistrationStatus: getCircuitRegistrationStatusFromString(isCircuitRegistrationResponse.circuit_registration_status),
            reductionCircuitHash: isCircuitRegistrationResponse.reduction_circuit_hash
        })
        return new IsCircuitResgisteredResponse(isCircuitRegistered);
    }

    public getRpcEndPoint() {
        return this.rpcEndPoint;
    }

    public getAuthToken() {
        return this.authToken;
    }

    public updateAuthToken(authToken: string) {
        this.authToken = authToken;
    }

    async checkServerConnection() {
        let isConnectionEstablished = false;
        try {
            let response = await checkServerConnection(this.rpcEndPoint, this.authToken);
            isConnectionEstablished = response == "pong" ? true : false;
        } catch (e: any) {
            console.log(e.message)
            if (e.message == "Unauthorized") {
                throw e;
            }
            isConnectionEstablished = false;
        }
        return isConnectionEstablished;
    }

    async registerSnarkJSGroth16Circuit(vkeyJsonFilePath: string): Promise<RegisterCircuitResponse> {
        const vkeyJson = checkPathAndReadJsonFile(vkeyJsonFilePath);
        let resp = await this.registerCircuit(vkeyJson, ProofType.GROTH16);
        return resp;
    }

    async registerGnarkGroth16Circuit(vkeyBinFilePath: string): Promise<RegisterCircuitResponse> {
        const vkeyBytes = checkPathAndReadFile(vkeyBinFilePath);
        const vkey = {
            vkey_bytes: Array.from(vkeyBytes)
        }
        let resp = await this.registerCircuit(vkey, ProofType.GNARK_GROTH16);
        return resp;
    }
    async registerGnarkPlonkCircuit(vkeyBinFilePath: string): Promise<RegisterCircuitResponse> {
        const vkeyBytes = checkPathAndReadFile(vkeyBinFilePath);
        const vkey = {
            vkey_bytes: Array.from(vkeyBytes)
        }
        let resp = await this.registerCircuit(vkey, ProofType.GNARK_PLONK);
        return resp;
    }

    async registerHalo2KZGEvmCircuit(sg2JsonFilePath: string, protocolJsonFilePath: string) {
        const sg2FileBytes = checkPathAndReadFile(sg2JsonFilePath)
        const protocolFileBytes = checkPathAndReadFile(protocolJsonFilePath);
        const halo2Vkey = {
            protocol_bytes: Array.from(protocolFileBytes),
            sg2_bytes: Array.from(sg2FileBytes),
        }
        let resp = await this.registerCircuit(halo2Vkey, ProofType.HALO2_PLONK);
        return resp;
    }

    async registerHalo2KZGCircuit(sg2JsonFilePath: string, protocolJsonFilePath: string) {
        const sg2FileBytes = checkPathAndReadFile(sg2JsonFilePath)
        const protocolFileBytes = checkPathAndReadFile(protocolJsonFilePath);
        const halo2Vkey = {
            protocol_bytes: Array.from(protocolFileBytes),
            sg2_bytes: Array.from(sg2FileBytes),
        }
        let resp = await this.registerCircuit(halo2Vkey, ProofType.HALO2_POSEIDON);
        return resp;
    }

    async registerPlonky2Circuit(commonCircuitDataBinFilePath: string, verifierOnlyBinFilePath: string) {
        const commonCircuitDataFileBytes = checkPathAndReadFile(commonCircuitDataBinFilePath)
        const verifierOnlyFileBytes = checkPathAndReadFile(verifierOnlyBinFilePath);
        const vkey = {
            common_bytes: Array.from(commonCircuitDataFileBytes),
            verifier_only_bytes: Array.from(verifierOnlyFileBytes),
        }
        let resp = await this.registerCircuit(vkey, ProofType.PLONKY2);
        return resp;
    }

    async registerRisc0Circuit(vkeyJsonPath: string) {
        const image_id = checkPathAndReadJsonFile(vkeyJsonPath);
        const vkey = {
            vkey_bytes: image_id 
        }
        let resp = await this.registerCircuit(vkey, ProofType.RISC0);
        return resp;
    }

    async registerSp1Circuit(vkeyBinFilePath: string) {
        const vkey_bytes = checkPathAndReadFile(vkeyBinFilePath);
        const vkey = {
            vkey_bytes 
        }
        let resp = await this.registerCircuit(vkey, ProofType.SP1);
        return resp;
    }

    private async registerCircuit(vKey: any, proofType: ProofType) {
        const serializedVKey = serializeVKey(vKey, proofType);

        const circuitHashString = await registerCircuit(this.rpcEndPoint, serializedVKey, proofType, this.authToken);
        let cirucitHash = Keccak256Hash.fromString(circuitHashString);
        return new RegisterCircuitResponse(cirucitHash);
    }

    // TODO: handle error from node
    async submitSnarkJSGroth16Proof(proofJsonPath: string, pisJsonFilePath: string, circuitHash: string): Promise<SubmitProofResponse> {
        Keccak256Hash.fromString(circuitHash);
        const proof = getProof(proofJsonPath, ProofType.GROTH16);
        const pubInput = getPis(pisJsonFilePath, ProofType.GROTH16);
        let resp = await this.submitProof(proof, pubInput, circuitHash, ProofType.GROTH16);
        return resp;
    }

    async submitGnarkPlonkProof(proofBinFilePath: string, pisJsonFilePath: string, circuitHash: string): Promise<SubmitProofResponse> {
        Keccak256Hash.fromString(circuitHash);
        const proof = getProof(proofBinFilePath, ProofType.GNARK_PLONK);
        const pubInput = getPis(pisJsonFilePath, ProofType.GNARK_PLONK);
        let resp = await this.submitProof(proof, pubInput, circuitHash, ProofType.GNARK_PLONK);
        return resp;
    }

    async submitGnarkGroth16Proof(proofBinFilePath: string, pisJsonFilePath: string, circuitHash: string): Promise<SubmitProofResponse> {
        Keccak256Hash.fromString(circuitHash);
        const proof = getProof(proofBinFilePath, ProofType.GNARK_GROTH16);
        const pubInput = getPis(pisJsonFilePath, ProofType.GNARK_GROTH16);
        let resp = await this.submitProof(proof, pubInput, circuitHash, ProofType.GNARK_GROTH16);
        return resp;
    }

    async submitHalo2KZGEvmProof(proofBinFilePath: string, instancesJsonFilepath: string, circuitHash: string): Promise<SubmitProofResponse> {
        Keccak256Hash.fromString(circuitHash);
        const proof = getProof(proofBinFilePath, ProofType.HALO2_PLONK);
        const pubInput = getPis(instancesJsonFilepath, ProofType.HALO2_PLONK);
        let resp = await this.submitProof(proof, pubInput, circuitHash, ProofType.HALO2_PLONK);
        return resp;
    }

    async submitHalo2KZGProof(proofBinFilePath: string, instancesJsonFilepath: string, circuitHash: string): Promise<SubmitProofResponse> {
        Keccak256Hash.fromString(circuitHash);
        const proof = getProof(proofBinFilePath, ProofType.HALO2_POSEIDON);
        const pubInput = getPis(instancesJsonFilepath, ProofType.HALO2_POSEIDON);
        let resp = await this.submitProof(proof, pubInput, circuitHash, ProofType.HALO2_POSEIDON);
        return resp;
    }

    async submitPlonky2Proof(proofBinFilePath: string, circuitHash: string): Promise<SubmitProofResponse> {
        Keccak256Hash.fromString(circuitHash);
        const proof = getProof(proofBinFilePath, ProofType.PLONKY2);
        const pubInput: string[] = [];
        let resp = await this.submitProof(proof, pubInput, circuitHash, ProofType.PLONKY2);
        return resp;
    }

    async submitRisc0Proof(receiptBinFilePath: string, circuitHash: string): Promise<SubmitProofResponse> {
        Keccak256Hash.fromString(circuitHash);
        const proof = getProof(receiptBinFilePath, ProofType.RISC0);
        const pubInput: string[] = [];
        let resp = await this.submitProof(proof, pubInput, circuitHash, ProofType.RISC0);
        return resp;
    }

    async submitSp1Proof(proofBinFilePath: string, circuitHash: string): Promise<SubmitProofResponse> {
        Keccak256Hash.fromString(circuitHash);
        const proof = getProof(proofBinFilePath, ProofType.SP1);
        const pubInput: string[] = [];
        let resp = await this.submitProof(proof, pubInput, circuitHash, ProofType.SP1);
        return resp;
    }

    private async submitProof(proof: any, pis: any, circuitHash: string, prooftype: ProofType) {
        const proofEncoded = serializeProof(proof, prooftype);
        const pubInputEncoded = serializePubInputs(pis, prooftype);
        
        let proofHashString = await submitProof(this.rpcEndPoint, proofEncoded, pubInputEncoded, circuitHash, prooftype, this.authToken);
        let proofHash = Keccak256Hash.fromString(proofHashString);
        return new SubmitProofResponse(proofHash)
    }

    async getProofData(proofHash: string): Promise<GetProofDataResponse> {
        Keccak256Hash.fromString(proofHash);
        let proofStatusResponse = await get_proof_status(this.rpcEndPoint, proofHash, this.authToken);
        let proofData = getProofStatusFromResponse(proofStatusResponse);
        return new GetProofDataResponse(proofData)
    }

    async getProtocolProof(proofHash: string): Promise<GetProtocolProofResponse> {
        Keccak256Hash.fromString(proofHash);
        let response = await getProtocolProof(this.rpcEndPoint, this.authToken, proofHash);
        let protocolProof = getProtocolProofFromResponse(response);
        return new GetProtocolProofResponse(protocolProof)
    }

    getProtocolInclusionProof(protocolProof: ProtocolProof): ProtocolInclusionProof {
        return {
            merkleProofPosition: protocolProof.merkleProofPosition,
            merkleProof: protocolProof.merkleProof,
        };
    }
}