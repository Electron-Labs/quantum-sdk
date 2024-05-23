export class SubmitProofResponse {
    proof_id: string;
    constructor(fields: any) {
        this.proof_id = fields.proof_id;
    }
}