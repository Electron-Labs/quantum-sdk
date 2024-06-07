export class ProtocolProof {
    public proof: number[][]
    public proofHelper: number[]
    constructor(fields: any) {
        this.proof = fields.proof
        this.proofHelper = fields.proofHelper
    }
}