export class RegisterCircuitResponse {
    circuit_hash: string;
    constructor(fields: any) {
        this.circuit_hash = fields.circuit_hash;
    }
}