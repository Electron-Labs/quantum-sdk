export class TransactionHash {
    private transactionHash: string;
    private constructor(hash: string){
        this.transactionHash = hash;
    }

    public static isTransactionalHashValid(hash: string) {
        return /^0x([A-Fa-f0-9]{64})$/.test(hash);
    }

    // TODO: define custom errors and return them
    public static fromString(value: string) {
        const isValid = this.isTransactionalHashValid(value);
        if (!isValid) {
            throw new Error("transaction hash is not valid");
        }
        return new TransactionHash(value); 
    } 

    public asString(){
        return this.transactionHash;
    }
}