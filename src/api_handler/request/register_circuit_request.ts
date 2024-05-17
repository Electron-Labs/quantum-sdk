export class RegisterCircuitRequest {
    vkey: number[]
    num_public_inputs: number
    proof_type: string
    constructor(fields: any) {
        this.vkey = fields.vkey;
        this.num_public_inputs = fields.num_public_inputs;
        this.proof_type = fields.proof_type
    }
}