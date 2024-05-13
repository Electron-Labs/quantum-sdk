"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ProofStatus = void 0;
class ProofStatus {
    constructor(fields) {
        this.state = fields.state;
        this.eta = fields.eta;
        this.superproofId = fields.superproofId;
        this.transactionHash = fields.transactionHash;
        this.verificationContract = fields.verificationContract;
    }
}
exports.ProofStatus = ProofStatus;
