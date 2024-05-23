import axios from "axios";
import { SubmitProof } from "./request/submit_proof_request";
import { SubmitProofResponse } from "./response/submit_proof_response";
import { ProofType } from "../enum/proof_type";

export async function submitProof(rpcEndPoint: string, proofEncoded: Uint8Array, publicInputsEncoded: Uint8Array, circuitId: String, proofType: ProofType) {
    const requestBody = getSubmitProofRequest(proofEncoded, publicInputsEncoded, circuitId, proofType);
    console.log({requestBody});
    try {
        const response = await axios.post(`${rpcEndPoint}/proof`, requestBody);
        const responseData: SubmitProofResponse = response.data;
        return responseData.proof_id;
    } catch(e) {
        // console.log(e);
        // TODO: throw different error based on different error code and message
        throw new Error("error in submit proof api " + JSON.stringify(e));
    }
}

function getSubmitProofRequest(proofEncoded: Uint8Array, publicInputsEncoded: Uint8Array, circuitId: String, proofType: ProofType) {
    return new SubmitProof({
        proof: Array.from(proofEncoded),
        pis: Array.from(publicInputsEncoded),
        circuit_hash: circuitId,
        proof_type: ProofType.asString(proofType)
    })
}