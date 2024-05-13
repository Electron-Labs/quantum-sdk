import { describe } from "mocha";
// import { TransactionHash } from "../src/types/transaction_hash";
import { assert } from "chai";
import { Keccak256Hash } from "../src/types/keccak256_hash";

describe("keccah256_hash", () => {
    const invalidHash = "0x4dc70783f07ab7c5397a2f8ce213e1ced2b6332322763563eac3ded0b537f3d";
    const validHash = "0x4dc70783f07ab7c5397a2f8ce213e1ced2b6332322763563eac3ded0b537f3d7";

    describe("checking isKeccak256HashValid function", () => {
        it("should return false on invalid hash", () => {
            const isValid = Keccak256Hash.isKeccak256HashValid(invalidHash);
            assert.equal(isValid, false, "doesn't return false on invalid hash");
        })

        it("should return true on valid hash", () => {
            const isValid = Keccak256Hash.isKeccak256HashValid(validHash);
            assert.equal(isValid, true, "doesn't return true on valid hash");
        })
    })

    describe("checking fromString Function", () => {
        it("should throw error when invalid hash is passed", () => {
            assert.throw(() => {Keccak256Hash.fromString(invalidHash)}, Error, "hash is not valid", "doesn't throw error on invalid hash");
        })

        it("should return Keccak256Hash object with valid hash", () => {
            const hashObject = Keccak256Hash.fromString(validHash);
            assert.ok(hashObject instanceof Keccak256Hash, "return object is not valid object type");
        })
    })

    describe("checking asString function", () => {
        it("return correct hash as string", () => {
            const hash = Keccak256Hash.fromString(validHash);
            const hashAsString = hash.asString();
            assert.equal(hashAsString, validHash, "hash string is not correct");
        })
    })
})