"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.TransactionHash = void 0;
class TransactionHash {
    constructor(hash) {
        this.transactionHash = hash;
    }
    static isTransactionalHashValid(hash) {
        return /^0x([A-Fa-f0-9]{64})$/.test(hash);
    }
    // TODO: define custom errors and return them
    static fromString(value) {
        const isValid = this.isTransactionalHashValid(value);
        if (!isValid) {
            throw new Error("transaction hash is not valid");
        }
        return new TransactionHash(value);
    }
    asString() {
        return this.transactionHash;
    }
}
exports.TransactionHash = TransactionHash;
