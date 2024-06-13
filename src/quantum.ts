import { checkServerConnection } from "./api_handler/check_server_connection";
import { getCircuitRegistrationStatus, registerCircuit } from "./api_handler/register_circuit";
import { get_proof_status, getProtocolProof, submitProof } from "./api_handler/submit_proof";
import { CircuitRegistrationStatus, getCircuitRegistrationStatusFromString } from "./enum/circuit_registration_status";
import { ProofType } from "./enum/proof_type";
import QuantumInterface from "./interface/quantum_interface";
import { getProofStatusFromResponse, getProtocolProofFromResponse, serializeProof, serializePubInputs, serializeVKey } from "./quantum_helper";
import { IsCircuitRegistered } from "./types/is_circuit_registered";
import { Keccak256Hash } from "./types/keccak256_hash";
import { ProofData } from "./types/proof_status";
import { GetProofDataResponse } from "./types/quantum-response/get_proof_data_response";
import { GetProtocolProofResponse } from "./types/quantum-response/get_protocol_proof_response";
import { IsCircuitResgisteredResponse } from "./types/quantum-response/is_circuit_registered_response";
import { RegisterCircuitResponse } from "./types/quantum-response/register_circuit_resposne";
import { SubmitProofResponse } from "./types/quantum-response/submit_proof_response";
import { checkPathAndReadJsonFile } from "./utils/file";
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

    async registerCircuit(vkeyPath: string, publicInputsCount: number, proofType: ProofType): Promise<RegisterCircuitResponse> {
        const vkeyJson = checkPathAndReadJsonFile(vkeyPath);
        const serializedVKey = serializeVKey(vkeyJson, proofType);

        const circuitHashString = await registerCircuit(this.rpcEndPoint, serializedVKey, publicInputsCount, proofType, this.authToken);
        let cirucitHash = Keccak256Hash.fromString(circuitHashString);
        return new RegisterCircuitResponse(cirucitHash);
    }

    // TODO: handle error from node
    async submitProof(proofPath: string, pisPath: string, circuitHash: string, proofType: ProofType): Promise<SubmitProofResponse> {
        Keccak256Hash.fromString(circuitHash);
        const proof = checkPathAndReadJsonFile(proofPath);
        const proofEncoded = serializeProof(proof, proofType);

        const pubInput = checkPathAndReadJsonFile(pisPath);
        const pubInputEncoded = serializePubInputs(pubInput, proofType);

        let proofHashString = await submitProof(this.rpcEndPoint, proofEncoded, pubInputEncoded, circuitHash, proofType, this.authToken);
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

    getProtocolInclusionProof(protocolProof: ProtocolProof, pubInputs: string[]): ProtocolInclusionProof {
        let pubInputsBytes = new Array<Uint8Array>(pubInputs.length)
        for (let i = 0; i < pubInputsBytes.length; i++) {
            pubInputsBytes[i] = toLeBytes32(pubInputs[i])
        }
        return {
            protocolVKeyHash: protocolProof.protocolVkeyHash,
            reductionVKeyHash: protocolProof.reductionVkeyHash,
            merkleProofPosition: protocolProof.merkleProofPosition,
            merkleProof: protocolProof.merkleProof,
            leafNextValue: protocolProof.leafNextValue,
            leafNextIdx: protocolProof.leafNextIndex,
            pubInputs: pubInputs.length ? pubInputsBytes : undefined,
        };
    }
}