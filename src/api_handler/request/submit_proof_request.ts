export class SubmitProof {
    proof: number[]
    pis: number[]
    circuit_hash: string
    proof_type: string
    constructor(fields: any) {
        this.proof = fields.proof,
        this.pis = fields.pis,
        this.circuit_hash = fields.circuit_hash
        this.proof_type = fields.proof_type
    }
}