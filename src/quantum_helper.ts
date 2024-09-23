import { ethers } from "ethers";
import { ProofDataResponse } from "./api_handler/response/proof_data_response";
import { ProtocolProofResponse } from "./api_handler/response/protocol_proof_response";
import { getProofStatusFromString } from "./enum/proof_status";
import { ProofType } from "./enum/proof_type";
import { getGnarkProofSchema, getGnarkPubInputsSchema, getGnarkVKeySchema, serializeGnarkProof } from "./types/borsh_schema/gnark";
import { getSnarkJSProofSchema, getSnarkJSPubInputSchema, getSnarkJSVkeySchema, serializeSnarkProof } from "./types/borsh_schema/SnarkJS";
import { ContractAddress } from "./types/contract";
import { Keccak256Hash } from "./types/keccak256_hash";
import { ProofData } from "./types/proof_status";
import { ProtocolProof } from "./types/protocol_proof";
import { borshDeserialize, borshSerialize } from "./utils/borsh";
import { hexToBytes } from "./utils/bytes";
import { getHalo2ProofSchema, getHalo2PubInputSchema, getHaloVKeySchema, serializeHaloProof } from "./types/borsh_schema/halo2";
import { checkPathAndReadFile, checkPathAndReadJsonFile } from "./utils/file";
import { getGnarkPlonkProofSchema, getGnarkPlonkPubInputsSchema, getGnarkPlonkVKeySchema, serializeGnarkPlonkProof } from "./types/borsh_schema/gnark_plonk";

export function getProtocolProofFromResponse(resp: ProtocolProofResponse) {
    return new ProtocolProof({ ...resp })
}

export function getProofStatusFromResponse(resp: ProofDataResponse) {
    let transactionHash = resp.transaction_hash != null ? Keccak256Hash.fromString(resp.transaction_hash) : null;
    let contractAddress = ContractAddress.fromString(resp.verification_contract);
    let proofStatus = getProofStatusFromString(resp.status);
    return new ProofData({
        status: proofStatus,
        superproofId: resp.superproof_id,
        transactionHash,
        verificationContract: contractAddress
    })
}

export function serializeVKey(vkeyJson: any, proofType: ProofType) {
    let vkeySchema;
    if (proofType == ProofType.GNARK_GROTH16) {
        vkeySchema = getGnarkVKeySchema();
    } else if (proofType == ProofType.GROTH16) {
        vkeySchema = getSnarkJSVkeySchema();
    } else if (proofType == ProofType.HALO2_PLONK) {
        vkeySchema = getHaloVKeySchema();
    } else if (proofType == ProofType.GNARK_PLONK) {
        vkeySchema = getGnarkPlonkVKeySchema();
    }
    const serializedVkey = borshSerialize(vkeySchema, vkeyJson);
    return serializedVkey;
}

// TODO: handle this serialize based on proving schemes in better way
export function serializeProof(proofJson: any, proofType: ProofType) {
    if (proofType == ProofType.GNARK_GROTH16) {
        return serializeGnarkProof(proofJson);
    } else if (proofType == ProofType.GROTH16) {
        return serializeSnarkProof(proofJson);
    } else if (proofType == ProofType.HALO2_PLONK) {
        return serializeHaloProof(proofJson);
    } else if (proofType == ProofType.GNARK_PLONK) {
        return serializeGnarkPlonkProof(proofJson);
    } else {
        throw new Error("unsupported proof scheme")
    }
}

export function serializePubInputs(pubInputsJson: any, proofType: ProofType) {
    let pubInputsSchema;
    if (proofType == ProofType.GNARK_GROTH16) {
        pubInputsSchema = getGnarkPubInputsSchema();
    } else if (proofType == ProofType.GROTH16) {
        pubInputsSchema = getSnarkJSPubInputSchema();
    } else if (proofType == ProofType.HALO2_PLONK) {
        pubInputsSchema = getHalo2PubInputSchema();
    } else if (proofType == ProofType.GNARK_PLONK) {
        pubInputsSchema = getGnarkPlonkPubInputsSchema();
    }
    const serializedVkey = borshSerialize(pubInputsSchema, pubInputsJson);
    return serializedVkey;
}

export function getProof(proofPath: string, proofType: ProofType): any {
    let proof: any;
    if(proofType == ProofType.GROTH16) {
        proof = checkPathAndReadJsonFile(proofPath);
    } else {
        const proofBytes = Array.from(checkPathAndReadFile(proofPath));
        proof = { proof_bytes: proofBytes }
    }
    return proof;
}

export function getPis(pisPath: string, proofType: ProofType): any {
    let pis: any;
    if(proofType == ProofType.HALO2_PLONK) {
        pis = Array.from(checkPathAndReadFile(pisPath));
    } else {
        pis = checkPathAndReadJsonFile(pisPath);
    }
    return pis;
}

export function getCombinedVKeyHash(protocolVkeyHash: string, reductionVkeyHash: string): string {
    const concat = new Uint8Array(64)
    concat.set(hexToBytes(protocolVkeyHash.slice(2)))
    concat.set(hexToBytes(reductionVkeyHash.slice(2)), 32)
    return ethers.keccak256(concat)
}

export function deserializeVkey(bytes: Uint8Array, proofType: ProofType) {
    let vkeySchema;
    if (proofType == ProofType.GNARK_GROTH16) {
        vkeySchema = getGnarkVKeySchema();
    } else if (proofType == ProofType.GROTH16) {
        vkeySchema = getSnarkJSVkeySchema();
    } else if (proofType == ProofType.HALO2_PLONK) {
        vkeySchema = getHaloVKeySchema();
    } else if (proofType == ProofType.GNARK_PLONK) {
        vkeySchema = getGnarkPlonkVKeySchema();
    }
    const decodedValue = borshDeserialize(vkeySchema, bytes);
    return decodedValue;
}

export function deserializeProof(bytes: Uint8Array, proofType: ProofType) {
    let pkeySchema;
    if (proofType == ProofType.GNARK_GROTH16) {
        pkeySchema = getGnarkProofSchema();
    } else if (proofType == ProofType.GROTH16) {
        pkeySchema = getSnarkJSProofSchema();
    } else if (proofType == ProofType.HALO2_PLONK) {
        pkeySchema = getHalo2ProofSchema();
    } else if (proofType == ProofType.GNARK_PLONK) {
        pkeySchema = getGnarkPlonkProofSchema();
    }
    const decodedValue = borshDeserialize(pkeySchema, bytes);
    return decodedValue;
}