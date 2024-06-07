export class ProtocolProofResponse {
    public proof: number[][]
    public proof_helper: number[]
    constructor(fields: any) {
        this.proof =  fields.proof;
        this.proof_helper = fields.proof_helper
    }
}