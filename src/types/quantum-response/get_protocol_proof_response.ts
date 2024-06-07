import { ProtocolProof } from "../protocol_proof";

export class GetProtocolProofResponse {
    protocolProof: ProtocolProof;
    constructor(protocolProof: ProtocolProof) {
        this.protocolProof = protocolProof
    } 
}