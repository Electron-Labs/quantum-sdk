export declare class TransactionHash {
    private transactionHash;
    private constructor();
    static isTransactionalHashValid(hash: string): boolean;
    static fromString(value: string): TransactionHash;
    asString(): string;
}
