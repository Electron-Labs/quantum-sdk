import { checkServerConnection } from "./api_handler/check_server_connection";
import { registerCircuit } from "./api_handler/register_circuit";
import { ProofType } from "./enum/proof_type";
import QuantumInterface from "./interface/quantum_interface";
import { getGnarkVKeySchema } from "./types/borsh_schema/gnark";
import { Keccak256Hash } from "./types/keccak256_hash";
import { ProofStatus } from "./types/proof_status";
import { boshSerialize } from "./utils/borsh";
import { readJsonFile } from "./utils/file";

export class Quantum implements QuantumInterface {
    private rpcEndPoint: string;
    constructor(rpcEndPoint: string) {
        this.rpcEndPoint = rpcEndPoint;
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

    private serializeVKey(vkeyJson: any) {
        const vkeySchema = getGnarkVKeySchema();
        const serializedVkey= boshSerialize(vkeySchema, vkeyJson);
        return serializedVkey;
    }

    async registerCircuit(vkeyPath: string, cdPath: string, proofType: ProofType): Promise<Keccak256Hash> {
        const vkeyJson = readJsonFile(vkeyPath);
        const serializedVKey = this.serializeVKey(vkeyJson);
        let cdSerialized = new Uint8Array();
        // TODO: handle case when cdPath is not empty string

        // if(cdPath != "") {
        //     const cdJson = readJsonFile(cdPath);
        // }
        const circuitHashString = await registerCircuit(this.rpcEndPoint, serializedVKey, cdSerialized, proofType);
        return Keccak256Hash.fromString(circuitHashString);
    }

    submitProof(proofPath: string, pisPath: string, circuitId: Keccak256Hash): Keccak256Hash {
        throw new Error("Method not implemented.");
    }
    getProofData(proofId: Keccak256Hash): ProofStatus {
        throw new Error("Method not implemented.");
    }
}