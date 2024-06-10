import axios from "axios";
import { ProofType } from "../enum/proof_type";
import { RegisterCircuitRequest } from "./request/register_circuit_request";
import { RegisterCircuitResponse } from "./response/register_circuit_response";
import { CircuitRegistrationStatusResponse } from "./response/circuit_registration_status_response";
import { getCircuitRegistrationStatusFromString } from "../enum/circuit_registration_status";
import { getRequestheader } from "./api_utils";

export async function registerCircuit(rpcEndPoint: string, vkeySerialized: Uint8Array, publicInputsCount: number, proofType: ProofType, authToken: string) {
    const headers = getRequestheader(authToken);
    const requestBody = getRegisterCircuitRequest(vkeySerialized, publicInputsCount, proofType);
    try {
        const response = await axios.post(`${rpcEndPoint}/register_circuit`, requestBody, {headers});
        const responseData: RegisterCircuitResponse = response.data;
        return responseData.circuit_hash;
    } catch(e) {
        // console.log(e);
        // TODO: throw different error based on different error code and message
        throw new Error("error in register circuit api " + JSON.stringify(e));
    }
}

export async function getCircuitRegistrationStatus(circuitHash: string, rpcEndPoint: string, authToken: string) {
    const headers = getRequestheader(authToken);
    try {
        const response = await axios.get(`${rpcEndPoint}/circuit/${circuitHash}/status`,{headers});
        const responseData: CircuitRegistrationStatusResponse = response.data;
        return responseData;
    } catch(e) {
        // console.log(e);
        // TODO: throw different error based on different error code and message
        throw new Error("error in register circuit api " + JSON.stringify(e));
    }
}

function getRegisterCircuitRequest( vkeySerialized: Uint8Array, publicInputsCount: number, proofType: ProofType) {
    const prooftypeString = ProofType.asString(proofType);
    return new RegisterCircuitRequest({
        vkey: Array.from(vkeySerialized),
        num_public_inputs: publicInputsCount,
        proof_type: prooftypeString
    })
}