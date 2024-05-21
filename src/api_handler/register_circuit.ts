import axios from "axios";
import { ProofType } from "../enum/proof_type";
import { RegisterCircuitRequest } from "./request/register_circuit_request";
import { RegisterCircuitResponse } from "./response/register_circuit_response";
import { CircuitRegistrationStatusResponse } from "./response/circuit_registration_status_response";
import { getCircuitRegistrationStatusFromString } from "../enum/circuit_registration_status";

export async function registerCircuit(rpcEndPoint: string, vkeySerialized: Uint8Array, publicInputsCount: number, proofType: ProofType) {
    const requestBody = getRegisterCircuitRequest(vkeySerialized, publicInputsCount, proofType);
    try {
        const response = await axios.post(`${rpcEndPoint}/register_circuit`, requestBody);
        const responseData: RegisterCircuitResponse = response.data;
        return responseData.circuit_hash;
    } catch(e) {
        // console.log(e);
        // TODO: throw different error based on different error code and message
        throw new Error("error in register circuit api " + JSON.stringify(e));
    }
}

export async function getCircuitRegistrationStatus(circuitId: string, rpcEndPoint: string) {
    try {
        const response = await axios.get(`${rpcEndPoint}/circuit/${circuitId}/status`,);
        const responseData: CircuitRegistrationStatusResponse = response.data;
        return getCircuitRegistrationStatusFromString(responseData.circuit_registration_status);
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