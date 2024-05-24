import { checkServerConnection } from "./api_handler/check_server_connection";
import { getCircuitRegistrationStatus, registerCircuit } from "./api_handler/register_circuit";
import { submitProof } from "./api_handler/submit_proof";
import { CircuitRegistrationStatus } from "./enum/circuit_registration_status";
import { ProofType } from "./enum/proof_type";
import QuantumInterface from "./interface/quantum_interface";
import { getGnarkProofSchema, getGnarkPubInputsSchema, getGnarkVKeySchema } from "./types/borsh_schema/gnark";
import { getSnarkJSProofSchema, getSnarkJSPubInputSchema, getSnarkJSVkeySchema } from "./types/borsh_schema/SnarkJS";
import { Keccak256Hash } from "./types/keccak256_hash";
import { ProofStatus } from "./types/proof_status";
import { borshSerialize } from "./utils/borsh";
import { checkIfPathExist, readJsonFile } from "./utils/file";

export class Quantum implements QuantumInterface {
    private rpcEndPoint: string;
    constructor(rpcEndPoint: string) {
        this.rpcEndPoint = rpcEndPoint;
    }
    async isCircuitRegistered(circuitId: Keccak256Hash): Promise<CircuitRegistrationStatus> {
       const circuitRegistrationStatus = await getCircuitRegistrationStatus(circuitId.asString(), this.rpcEndPoint);
       return circuitRegistrationStatus;
    }

    public getRpcEndPoint() {
        return this.rpcEndPoint;
    }

    async checkServerConnection(){
        let isConnectionEstablished = false;
        try {
            let response = await checkServerConnection(this.rpcEndPoint);
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

        const circuitHashString = await registerCircuit(this.rpcEndPoint, serializedVKey, publicInputsCount, proofType);
        return Keccak256Hash.fromString(circuitHashString);
    }

    async submitProof(proofPath: string, pisPath: string, circuitId: string, proofType: ProofType): Promise<Keccak256Hash> {
        const circuitHash = Keccak256Hash.fromString(circuitId);
        const proof = this.checkPathAndReadJsonFile(proofPath);
        const proofEncoded = this.serializeProof(proof, proofType);

        const pubInput = this.checkPathAndReadJsonFile(pisPath);
        const pubInputEncoded = this.serializePubInputs(pubInput, proofType);

        let proofId = await submitProof(this.rpcEndPoint, proofEncoded, pubInputEncoded, circuitId, proofType);
        return Keccak256Hash.fromString(proofId);
    }

    getProofData(proofId: Keccak256Hash): ProofStatus {
        throw new Error("Method not implemented.");
    }
}