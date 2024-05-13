export declare class ContractAddress {
    private address;
    private constructor();
    static isContractAddressValid(address: string): boolean;
    static fromString(value: string): ContractAddress;
    asString(): string;
}
