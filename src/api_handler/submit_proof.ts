import axios from "axios";
import { SubmitProof } from "./request/submit_proof_request";
import { SubmitProofResponse } from "./response/submit_proof_response";
import { ProofType } from "../enum/proof_type";
import { ProofDataResponse } from "./response/proof_data_response";
import { getRequestheader } from "./api_utils";
import { ProtocolProofResponse } from "./response/protocol_proof_response";

export async function submitProof(rpcEndPoint: string, proofEncoded: Uint8Array, publicInputsEncoded: Uint8Array, circuitHash: String, proofType: ProofType, authToken: string) {
    const headers = getRequestheader(authToken);
    const requestBody = getSubmitProofRequest(proofEncoded, publicInputsEncoded, circuitHash, proofType);
    console.log({requestBody});
    try {
        const response = await axios.post(`${rpcEndPoint}/proof`, requestBody, {headers});
        const responseData: SubmitProofResponse = response.data;
        return responseData.proof_id;
    } catch(e) {
        // console.log(e);
        // TODO: throw different error based on different error code and message
        throw new Error("error in submit proof api " + JSON.stringify(e));
    }
}

export async function get_proof_status(rpcEndPoint: string, proof_id: string, authToken: string) {
    const headers = getRequestheader(authToken);
    try {
        const response = await axios.get(`${rpcEndPoint}/proof/${proof_id}`,{headers});
        const responseData: ProofDataResponse = response.data;
        console.log({responseData});
        return responseData;
    } catch(e) {
        // console.log(e);
        // TODO: throw different error based on different error code and message
        throw new Error("error in proof status api " + JSON.stringify(e));
    }
}

function getSubmitProofRequest(proofEncoded: Uint8Array, publicInputsEncoded: Uint8Array, circuitHash: String, proofType: ProofType) {
    return new SubmitProof({
        proof: Array.from(proofEncoded),
        pis: Array.from(publicInputsEncoded),
        circuit_hash: circuitHash,
        proof_type: ProofType.asString(proofType)
    })
}

export async function getProtocolProof(rpcEndPoint: string, authToken: string, proofHash: string) {
    const headers = getRequestheader(authToken);
    try {
        const response = await axios.get(`${rpcEndPoint}/protocol_proof/merkle/${proofHash}`,{headers});
        const responseData: ProtocolProofResponse = response.data;
        console.log({responseData});
        return responseData;
    } catch(e) {
        // console.log(e);
        // TODO: throw different error based on different error code and message
        throw new Error("error in proof status api " + JSON.stringify(e));
    }
}