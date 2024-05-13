"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const chai_1 = require("chai");
const mocha_1 = require("mocha");
const contract_1 = require("../src/types/contract");
(0, mocha_1.describe)("contract_address", () => {
    const invalidContractAddress = "0xDF11C90D1882257690Dca8f6b5013CFd75aBf34";
    const validContractAddress = "0xDF11C90D1882257690Dca8f6b5013CFd75aBf347";
    (0, mocha_1.describe)("checking isContractAddressValid function", () => {
        it("should return false on invalid contract address", () => {
            const isValid = contract_1.ContractAddress.isContractAddressValid(invalidContractAddress);
            chai_1.assert.equal(isValid, false, "doesn't return false on invalid contract address");
        });
        it("should return true on valid contract address", () => {
            const isValid = contract_1.ContractAddress.isContractAddressValid(validContractAddress);
            chai_1.assert.equal(isValid, true, "doesn't return true on valid contract address");
        });
    });
    (0, mocha_1.describe)("checking fromString Function", () => {
        it("should throw error when invalid contract address is passed", () => {
            chai_1.assert.throw(() => { contract_1.ContractAddress.fromString(invalidContractAddress); }, Error, "contract address is not valid", "doesn't throw error on invalid contract address");
        });
        it("should return ContractAddress object with valid address", () => {
            const contractAddressObject = contract_1.ContractAddress.fromString(validContractAddress);
            chai_1.assert.ok(contractAddressObject instanceof contract_1.ContractAddress, "return object is not valid object type");
        });
    });
    (0, mocha_1.describe)("checking asString function", () => {
        it("return correct transaction hash as string", () => {
            const hash = contract_1.ContractAddress.fromString(validContractAddress);
            const hashAsString = hash.asString();
            chai_1.assert.equal(hashAsString, validContractAddress, "contract address string is not correct");
        });
    });
});
