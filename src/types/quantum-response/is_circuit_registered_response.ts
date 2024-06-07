import { CircuitRegistrationStatus } from "../../enum/circuit_registration_status";
import { IsCircuitRegistered } from "../is_circuit_registered";

export class IsCircuitResgisteredResponse {
    isCircuitRegistered: IsCircuitRegistered
    constructor(isCircuitRegistered: IsCircuitRegistered) {
        this.isCircuitRegistered = isCircuitRegistered
    }
}