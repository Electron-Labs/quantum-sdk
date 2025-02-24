export enum ProofType {
    GROTH16 = 1,
    GNARK_GROTH16 = 2,
    PLONKY2 = 3,
    HALO2_PLONK = 4,
    GNARK_PLONK = 5,
    HALO2_POSEIDON = 6,
    RISC0 = 7,
    SP1 = 8,
    NITRO_ATT = 9,
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
            case ProofType.GNARK_PLONK:
                return 'GnarkPlonk';
            case ProofType.HALO2_POSEIDON:
                return 'Halo2Poseidon'
            case ProofType.RISC0:
                return 'Risc0'
            case ProofType.SP1:
                return 'Sp1'
            case ProofType.NITRO_ATT:
                return 'NitroAtt'
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
            case  'Halo2Plonk'.toLowerCase() :
                return ProofType.HALO2_PLONK;
            case  'GnarkPlonk'.toLowerCase() :
                return ProofType.GNARK_PLONK;
            case 'Halo2_Poseidon'.toLowerCase():
                return ProofType.HALO2_POSEIDON
            case 'Halo2Poseidon'.toLowerCase():
                return ProofType.HALO2_POSEIDON
            case 'Risc0'.toLowerCase():
                return ProofType.RISC0
            case 'Sp1'.toLowerCase():
                return ProofType.SP1
            case 'NitroAtt'.toLowerCase():
                return ProofType.NITRO_ATT
            default:
                throw new Error('Unknown proof type');
        }
    }
}