"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const mocha_1 = require("mocha");
const transaction_hash_1 = require("../src/types/transaction_hash");
const chai_1 = require("chai");
(0, mocha_1.describe)("transaction_hash", () => {
    const invalidTransactionHash = "0x4dc70783f07ab7c5397a2f8ce213e1ced2b6332322763563eac3ded0b537f3d";
    const validTransactionHash = "0x4dc70783f07ab7c5397a2f8ce213e1ced2b6332322763563eac3ded0b537f3d7";
    (0, mocha_1.describe)("checking isTransactionHashValid function", () => {
        it("should return false on invalid transaction hash", () => {
            const isValid = transaction_hash_1.TransactionHash.isTransactionalHashValid(invalidTransactionHash);
            chai_1.assert.equal(isValid, false, "doesn't return false on invalid transaction hash");
        });
        it("should return true on valid transaction hash", () => {
            const isValid = transaction_hash_1.TransactionHash.isTransactionalHashValid(validTransactionHash);
            chai_1.assert.equal(isValid, true, "doesn't return true on valid transaction hash");
        });
    });
    (0, mocha_1.describe)("checking fromString Function", () => {
        it("should throw error when invalid transaction hash is passed", () => {
            chai_1.assert.throw(() => { transaction_hash_1.TransactionHash.fromString(invalidTransactionHash); }, Error, "transaction hash is not valid", "doesn't throw error on invalid transaction hash");
        });
        it("should return TransactionHash object with valid hash", () => {
            const transactionHashObject = transaction_hash_1.TransactionHash.fromString(validTransactionHash);
            chai_1.assert.ok(transactionHashObject instanceof transaction_hash_1.TransactionHash, "return object is not valid object type");
        });
    });
    (0, mocha_1.describe)("checking asString function", () => {
        it("return correct transaction hash as string", () => {
            const hash = transaction_hash_1.TransactionHash.fromString(validTransactionHash);
            const hashAsString = hash.asString();
            chai_1.assert.equal(hashAsString, validTransactionHash, "transaction hash string is not correct");
        });
    });
});
