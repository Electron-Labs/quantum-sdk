import { checkServerConnection } from "./api_handler/check_server_connection";
import { getCircuitRegistrationStatus, registerCircuit } from "./api_handler/register_circuit";
import { CircuitRegistrationStatus } from "./enum/circuit_registration_status";
import { ProofType } from "./enum/proof_type";
import QuantumInterface from "./interface/quantum_interface";
import { getGnarkVKeySchema } from "./types/borsh_schema/gnark";
import { getSnarkJSVkeySchema } from "./types/borsh_schema/SnarkJS";
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

    public readVkey(vkeyPath: string) {
        let isPathExist = checkIfPathExist(vkeyPath);
        if(!isPathExist) {
            throw new Error(`VkeyPath does not exist : ${vkeyPath}.`);
        }
        return readJsonFile(vkeyPath);
    }

    async registerCircuit(vkeyPath: string, publicInputsCount: number, proofType: ProofType): Promise<Keccak256Hash> {
        const vkeyJson = this.readVkey(vkeyPath);
        const serializedVKey = this.serializeVKey(vkeyJson, proofType);

        const circuitHashString = await registerCircuit(this.rpcEndPoint, serializedVKey, publicInputsCount, proofType);
        return Keccak256Hash.fromString(circuitHashString);
    }

    submitProof(proofPath: string, pisPath: string, circuitId: Keccak256Hash): Keccak256Hash {
        throw new Error("Method not implemented.");
    }
    getProofData(proofId: Keccak256Hash): ProofStatus {
        throw new Error("Method not implemented.");
    }
}