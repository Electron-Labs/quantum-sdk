import { ethers } from "ethers";
import { ProofState } from "../enum/proof_state";
import { ContractAddress } from "./contract";
import { Keccak256Hash } from "./keccak256_hash";

export class ProofStatus {
    public state: ProofState;
    public eta: number;
    public superproofId: Keccak256Hash;
    public transactionHash: Keccak256Hash;
    public verificationContract: ContractAddress;
    constructor(fields: any) {
        this.state = fields.state;
        this.eta = fields.eta;
        this.superproofId = fields.superproofId;
        this.transactionHash = fields.transactionHash;
        this.verificationContract = fields.verificationContract;
    }
}