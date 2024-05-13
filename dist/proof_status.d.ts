import { ProofState } from "./enum/proof_state";
export declare class ProofStatus {
    state: ProofState;
    eta: number;
    superproofId: string;
    transactionHash: string;
    verificationContract: string;
    constructor(fields: any);
}
