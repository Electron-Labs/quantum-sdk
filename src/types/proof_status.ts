import { ethers } from "ethers";
import { ContractAddress } from "./contract";
import { Keccak256Hash } from "./keccak256_hash";
import { ProofStatus } from "../enum/proof_status";

export class ProofData {
    public status: ProofStatus;
    public superproofId: number;
    public transactionHash: Keccak256Hash | null;
    public verificationContract: ContractAddress;
    constructor(fields: any) {
        this.status = fields.status;
        this.superproofId = fields.superproofId;
        this.transactionHash = fields.transactionHash;
        this.verificationContract = fields.verificationContract;
    }
}