import { describe } from "mocha";
import { TransactionHash } from "../src/types/transaction_hash";
import { assert } from "chai";

describe("transaction_hash", () => {
    const invalidTransactionHash = "0x4dc70783f07ab7c5397a2f8ce213e1ced2b6332322763563eac3ded0b537f3d";
    const validTransactionHash = "0x4dc70783f07ab7c5397a2f8ce213e1ced2b6332322763563eac3ded0b537f3d7";

    describe("checking isTransactionHashValid function", () => {
        it("should return false on invalid transaction hash", () => {
            const isValid = TransactionHash.isTransactionalHashValid(invalidTransactionHash);
            assert.equal(isValid, false, "doesn't return false on invalid transaction hash");
        })

        it("should return true on valid transaction hash", () => {
            
            const isValid = TransactionHash.isTransactionalHashValid(validTransactionHash);
            assert.equal(isValid, true, "doesn't return true on valid transaction hash");
        })
    })

    describe("checking fromString Function", () => {
        it("should throw error when invalid transaction hash is passed", () => {
            assert.throw(() => {TransactionHash.fromString(invalidTransactionHash)}, Error, "transaction hash is not valid", "doesn't throw error on invalid transaction hash");
        })

        it("should return TransactionHash object with valid hash", () => {
            const transactionHashObject = TransactionHash.fromString(validTransactionHash);
            assert.ok(transactionHashObject instanceof TransactionHash, "return object is not valid object type");
        })
    })

    describe("checking asString function", () => {
        it("return correct transaction hash as string", () => {
            const hash = TransactionHash.fromString(validTransactionHash);
            const hashAsString = hash.asString();
            assert.equal(hashAsString, validTransactionHash, "transaction hash string is not correct");
        })
    })
})