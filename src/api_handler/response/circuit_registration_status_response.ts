export class CircuitRegistrationStatusResponse {
    circuit_registration_status: string;
    reduction_circuit_hash: string | null = null
    constructor(fields: any) {
        this.circuit_registration_status = fields.circuit_registration_status;
        this.reduction_circuit_hash = fields.reduction_circuit_hash
    }
}