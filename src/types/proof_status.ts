import { ethers } from "ethers";
import { ProofState } from "../enum/proof_state";
import { TransactionHash } from "./transaction_hash";
import { ContractAddress } from "./contract";

export class ProofStatus {
    public state: ProofState;
    public eta: number;
    public superproofId: string;
    public transactionHash: TransactionHash;
    public verificationContract: ContractAddress;
    constructor(fields: any) {
        this.state = fields.state;
        this.eta = fields.eta;
        this.superproofId = fields.superproofId;
        this.transactionHash = fields.transactionHash;
        this.verificationContract = fields.verificationContract;
    }
}