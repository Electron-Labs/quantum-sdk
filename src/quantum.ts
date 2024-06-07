import { checkServerConnection } from "./api_handler/check_server_connection";
import { getCircuitRegistrationStatus, registerCircuit } from "./api_handler/register_circuit";
import { get_proof_status, getProtocolProof, submitProof } from "./api_handler/submit_proof";
import { CircuitRegistrationStatus } from "./enum/circuit_registration_status";
import { ProofType } from "./enum/proof_type";
import QuantumInterface from "./interface/quantum_interface";
import { getProofStatusFromResponse, getProtocolProofFromResponse, serializeProof, serializePubInputs, serializeVKey } from "./quantum_helper";
import { Keccak256Hash } from "./types/keccak256_hash";
import { ProofData } from "./types/proof_status";
import { checkPathAndReadJsonFile } from "./utils/file";

export class Quantum implements QuantumInterface {
    private rpcEndPoint: string;
    private authToken: string;
    constructor(rpcEndPoint: string, authToken:  string) {
        this.rpcEndPoint = rpcEndPoint;
        this.authToken = authToken;
    }
    async isCircuitRegistered(circuitId: string): Promise<CircuitRegistrationStatus> {
       const circuit_hash = Keccak256Hash.fromString(circuitId);
       const circuitRegistrationStatus = await getCircuitRegistrationStatus(circuitId, this.rpcEndPoint, this.authToken);
       return circuitRegistrationStatus;
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
        } catch(e: any) {
            if(e.message == "Unauthorized"){
                throw e;
            }
            isConnectionEstablished = false;
        }
        return isConnectionEstablished;
    }

    async registerCircuit(vkeyPath: string, publicInputsCount: number, proofType: ProofType): Promise<Keccak256Hash> {
        const vkeyJson = checkPathAndReadJsonFile(vkeyPath);
        const serializedVKey = serializeVKey(vkeyJson, proofType);

        const circuitHashString = await registerCircuit(this.rpcEndPoint, serializedVKey, publicInputsCount, proofType, this.authToken);
        return Keccak256Hash.fromString(circuitHashString);
    }

    // TODO: handle error from node
    async submitProof(proofPath: string, pisPath: string, circuitId: string, proofType: ProofType): Promise<Keccak256Hash> {
        Keccak256Hash.fromString(circuitId);
        const proof = checkPathAndReadJsonFile(proofPath);
        const proofEncoded = serializeProof(proof, proofType);

        const pubInput = checkPathAndReadJsonFile(pisPath);
        const pubInputEncoded = serializePubInputs(pubInput, proofType);

        let proofId = await submitProof(this.rpcEndPoint, proofEncoded, pubInputEncoded, circuitId, proofType, this.authToken);
        return Keccak256Hash.fromString(proofId);
    }

    async getProofData(proofId: string): Promise<ProofData> {
        Keccak256Hash.fromString(proofId);
        let proofStatusResponse = await get_proof_status(this.rpcEndPoint, proofId, this.authToken);
        return getProofStatusFromResponse(proofStatusResponse);
    }

    async getProtocolProof(proofId: string) {
        Keccak256Hash.fromString(proofId);
        let response = await getProtocolProof(this.rpcEndPoint, this.authToken, proofId);
        return getProtocolProofFromResponse(response);
    }

   
}