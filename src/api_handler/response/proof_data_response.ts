export class ProofDataResponse {
    public status: string;
    public superproof_id: number;
    public transaction_hash: string | null;
    public verification_contract: string;
    constructor(fields: any) {
        this.status = fields.status;
        this.superproof_id = fields.superproof_id;
        this.transaction_hash = fields.transaction_hash;
        this.verification_contract = fields.verification_contract;
    }
}