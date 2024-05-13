import { ProofState } from "../enum/proof_state";
import { TransactionHash } from "./transaction_hash";
import { ContractAddress } from "./contract";
export declare class ProofStatus {
    state: ProofState;
    eta: number;
    superproofId: string;
    transactionHash: TransactionHash;
    verificationContract: ContractAddress;
    constructor(fields: any);
}
