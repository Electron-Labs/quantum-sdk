import { CircuitRegistrationStatus } from "../../enum/circuit_registration_status";

export class IsCircuitResgisteredResponse {
    isCircuitRegistered: CircuitRegistrationStatus
    constructor(status: CircuitRegistrationStatus) {
        this.isCircuitRegistered = status
    }
}