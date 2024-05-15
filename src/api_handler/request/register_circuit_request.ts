export class RegisterCircuitRequest {
    vkey: number[]
    cd: number[]
    proof_type: string
    constructor(fields: any) {
        this.vkey = fields.vkey;
        this.cd = fields.cd;
        this.proof_type = fields.proof_type
    }
}