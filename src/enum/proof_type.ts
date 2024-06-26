export enum ProofType {
    GROTH16 = 1,
    GNARK_GROTH16 = 2,
    PLONKY2 = 3,
    HALO2_PLONK = 4 
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
            case ProofType.HALO2_PLONK:
                return 'Halo2Plonk';
            default:
                throw new Error('Unknown proof type');
        }
    }

    export function fromString(type: string) {
        switch (type.toLocaleLowerCase()) {
            case "Groth16".toLowerCase():
                return ProofType.GROTH16;
            case 'Gnark_Groth16'.toLowerCase():
                return  ProofType.GNARK_GROTH16;
            case  'Plonky2'.toLowerCase():
                return ProofType.PLONKY2;
            case 'Halo2_Plonk'.toLowerCase():
                return ProofType.HALO2_PLONK;
            case 'GnarkGroth16'.toLowerCase():
                return  ProofType.GNARK_GROTH16;
            case  'Halo2Plonk' :
                return ProofType.HALO2_PLONK;
            default:
                throw new Error('Unknown proof type');
        }
    }
}