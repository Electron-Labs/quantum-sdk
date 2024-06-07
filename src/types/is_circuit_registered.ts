export class IsCircuitRegistered {
    circuitRegistrationStatus: string;
    reductionCircuitHash: string | null = null
    constructor(fields: any) {
        this.circuitRegistrationStatus = fields.circuitRegistrationStatus;
        this.reductionCircuitHash = fields.reductionCircuitHash
    }
}