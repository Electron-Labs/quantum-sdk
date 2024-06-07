import { ProofData } from "../proof_status";

export class GetProofDataResponse{
    proofData: ProofData
    constructor(proofData: ProofData) {
        this.proofData = proofData
    }
}