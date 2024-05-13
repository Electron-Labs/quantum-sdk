"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ContractAddress = void 0;
const ethers_1 = require("ethers");
class ContractAddress {
    constructor(address) {
        this.address = address;
    }
    static isContractAddressValid(address) {
        return ethers_1.ethers.isAddress(address);
    }
    // TODO: define custom error and return them
    static fromString(value) {
        let isValid = this.isContractAddressValid(value);
        if (!isValid) {
            throw new Error("contract address is not valid");
        }
        return new ContractAddress(value);
    }
    asString() {
        return this.address;
    }
}
exports.ContractAddress = ContractAddress;
