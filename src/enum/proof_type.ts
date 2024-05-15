export enum ProofType {
    GROTH16 = 1,
    GNARK_GROTH16 = 2,
    PLONKY2 = 3,
    HALO2_KZG = 4 
}

export namespace ProofType {
    export function asString(type: ProofType) {
        switch (type) {
            case ProofType.GROTH16:
                return 'Groth16';
            case ProofType.GNARK_GROTH16:
                return 'GnarkGroth16';
            case ProofType.PLONKY2:
                return 'Plonky2';
            case ProofType.HALO2_KZG:
                return 'Halo2KZG';
            default:
                throw new Error('Unknown proof type');
        }
    }
}