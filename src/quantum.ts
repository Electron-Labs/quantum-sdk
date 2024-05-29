import { checkServerConnection } from "./api_handler/check_server_connection";
import { getCircuitRegistrationStatus, registerCircuit } from "./api_handler/register_circuit";
import { ProofDataResponse } from "./api_handler/response/proof_data_response";
import { get_proof_status, submitProof } from "./api_handler/submit_proof";
import { CircuitRegistrationStatus } from "./enum/circuit_registration_status";
import { getProofStatusFromString } from "./enum/proof_status";
import { ProofType } from "./enum/proof_type";
import QuantumInterface from "./interface/quantum_interface";
import { getGnarkProofSchema, getGnarkPubInputsSchema, getGnarkVKeySchema } from "./types/borsh_schema/gnark";
import { getSnarkJSProofSchema, getSnarkJSPubInputSchema, getSnarkJSVkeySchema } from "./types/borsh_schema/SnarkJS";
import { ContractAddress } from "./types/contract";
import { Keccak256Hash } from "./types/keccak256_hash";
import { ProofData } from "./types/proof_status";
import { borshSerialize } from "./utils/borsh";
import { checkIfPathExist, readJsonFile } from "./utils/file";

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

    async checkServerConnection(){
        let isConnectionEstablished = false;
        try {
            let response = await checkServerConnection(this.rpcEndPoint, this.authToken);
            isConnectionEstablished = response == "pong" ? true : false;
        } catch(e) {
            isConnectionEstablished = false;
        }
        return isConnectionEstablished;
    }

    private serializeVKey(vkeyJson: any, proofType: ProofType) {
        let vkeySchema;
        if (proofType == ProofType.GNARK_GROTH16) {
            vkeySchema = getGnarkVKeySchema();
        } else if (proofType == ProofType.GROTH16) {
            vkeySchema = getSnarkJSVkeySchema();
        }
        const serializedVkey= borshSerialize(vkeySchema, vkeyJson);
        return serializedVkey;
    }

    // TODO: handle this serialize based on proving schemes in better way
    private serializeProof(proofJson: any, proofType: ProofType) {
        let proofSchema;
        if (proofType == ProofType.GNARK_GROTH16) {
            proofSchema = getGnarkProofSchema();
        } else if (proofType == ProofType.GROTH16) {
            proofSchema = getSnarkJSProofSchema();
        }
        const serializedVkey= borshSerialize(proofSchema, proofJson);
        return serializedVkey;
    }

    private serializePubInputs(pubInputsJson: any, proofType: ProofType) {
        let pubInputsSchema;
        if (proofType == ProofType.GNARK_GROTH16) {
            pubInputsSchema = getGnarkPubInputsSchema();
        } else if (proofType == ProofType.GROTH16) {
            pubInputsSchema = getSnarkJSPubInputSchema();
        }
        const serializedVkey= borshSerialize(pubInputsSchema, pubInputsJson);
        return serializedVkey;
    }

    public checkPathAndReadJsonFile(vkeyPath: string) {
        let isPathExist = checkIfPathExist(vkeyPath);
        if(!isPathExist) {
            throw new Error(`VkeyPath does not exist : ${vkeyPath}.`);
        }
        return readJsonFile(vkeyPath);
    }

    async registerCircuit(vkeyPath: string, publicInputsCount: number, proofType: ProofType): Promise<Keccak256Hash> {
        const vkeyJson = this.checkPathAndReadJsonFile(vkeyPath);
        const serializedVKey = this.serializeVKey(vkeyJson, proofType);

        const circuitHashString = await registerCircuit(this.rpcEndPoint, serializedVKey, publicInputsCount, proofType, this.authToken);
        return Keccak256Hash.fromString(circuitHashString);
    }

    // TODO: handle error from node
    async submitProof(proofPath: string, pisPath: string, circuitId: string, proofType: ProofType): Promise<Keccak256Hash> {
        Keccak256Hash.fromString(circuitId);
        const proof = this.checkPathAndReadJsonFile(proofPath);
        const proofEncoded = this.serializeProof(proof, proofType);

        const pubInput = this.checkPathAndReadJsonFile(pisPath);
        const pubInputEncoded = this.serializePubInputs(pubInput, proofType);

        let proofId = await submitProof(this.rpcEndPoint, proofEncoded, pubInputEncoded, circuitId, proofType, this.authToken);
        return Keccak256Hash.fromString(proofId);
    }

    async getProofData(proofId: string): Promise<ProofData> {
        Keccak256Hash.fromString(proofId);
        let proofStatusResponse = await get_proof_status(this.rpcEndPoint, proofId, this.authToken);
        return this.getProofStatusFromResponse(proofStatusResponse);
    }

    private getProofStatusFromResponse(resp: ProofDataResponse) {
        let transactionHash = resp.transaction_hash != null ? Keccak256Hash.fromString(resp.transaction_hash) : null;
        let contractAddress = ContractAddress.fromString(resp.verification_contract);
        let proofStatus = getProofStatusFromString(resp.status);
        return new ProofData({
            status: proofStatus,
            superproofId: resp.superproof_id,
            transactionHash,
            verificationContract: contractAddress
        })
    }
}