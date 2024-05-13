import { ethers } from "ethers";

export class ContractAddress {
    private address: string;
    private constructor(address: string) {
        this.address = address;
    }

    public static isContractAddressValid(address: string) {
        return ethers.isAddress(address);
    }

    // TODO: define custom error and return them
    public static fromString(value: string) {
        let isValid = this.isContractAddressValid(value);
        if(!isValid ) {
            throw new Error("contract address is not valid");
        }
        return new ContractAddress(value); 
    }

    public asString() {
        return this.address;
    }
}