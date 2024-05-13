export class Keccak256Hash {
    private hash: string;
    private constructor(hash: string){
        this.hash = hash;
    }

    public static isKeccak256HashValid(hash: string) {
        return /^0x([A-Fa-f0-9]{64})$/.test(hash);
    }

    // TODO: define custom errors and return them
    public static fromString(value: string) {
        const isValid = this.isKeccak256HashValid(value);
        if (!isValid) {
            throw new Error("hash is not valid");
        }
        return new Keccak256Hash(value); 
    } 

    public asString(){
        return this.hash;
    }
}