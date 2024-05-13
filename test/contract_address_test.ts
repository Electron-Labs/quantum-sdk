import { assert } from "chai";
import { describe } from "mocha";
import { ContractAddress } from "../src/types/contract";

describe("contract_address", () => {
    const invalidContractAddress = "0xDF11C90D1882257690Dca8f6b5013CFd75aBf34";
    const validContractAddress = "0xDF11C90D1882257690Dca8f6b5013CFd75aBf347";

    describe("checking isContractAddressValid function", () => {
        it("should return false on invalid contract address", () => {
            const isValid = ContractAddress.isContractAddressValid(invalidContractAddress);
            assert.equal(isValid, false, "doesn't return false on invalid contract address");
        })

        it("should return true on valid contract address", () => {
            const isValid = ContractAddress.isContractAddressValid(validContractAddress);
            assert.equal(isValid, true, "doesn't return true on valid contract address");
        })
    })

    describe("checking fromString Function", () => {
        it("should throw error when invalid contract address is passed", () => {
            assert.throw(() => {ContractAddress.fromString(invalidContractAddress)}, Error, "contract address is not valid", "doesn't throw error on invalid contract address");
        })

        it("should return ContractAddress object with valid address", () => {
            const contractAddressObject = ContractAddress.fromString(validContractAddress);
            assert.ok(contractAddressObject instanceof ContractAddress, "return object is not valid object type");
        })
    })

    describe("checking asString function", () => {
        it("return correct transaction hash as string", () => {
            const hash = ContractAddress.fromString(validContractAddress);
            const hashAsString = hash.asString();
            assert.equal(hashAsString, validContractAddress, "contract address string is not correct");
        })
    })
})