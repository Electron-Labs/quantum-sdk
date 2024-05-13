import { ProofState } from "./enum/proof_state";

export class ProofStatus {
    public state: ProofState;
    public eta: number;
    public superproofId: string;
    public transactionHash: string;
    public verificationContract: string;
    constructor(fields: any) {
        this.state = fields.state;
        this.eta = fields.eta;
        this.superproofId = fields.superproofId;
        this.transactionHash = fields.transactionHash;
        this.verificationContract = fields.verificationContract;
    } 
}