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
import { getHalo2PoseidonProofSchema, getHalo2PoseidonPubInputSchema, getHalo2PoseidonVKeySchema } from "./types/borsh_schema/halo2_poseidon";
import { getPlonky2ProofSchema, getPlonky2PubInputSchema, getPlonky2VKeySchema } from "./types/borsh_schema/plonky2";

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
    let {vkeySchema, proofSchema , pisSchema } = getBorshSchemaForProvingScheme(proofType);
    const serializedVkey = borshSerialize(vkeySchema, vkeyJson);
    return serializedVkey;
}

export function serializeProof(proofJson: any, proofType: ProofType) {
    let {vkeySchema, proofSchema , pisSchema } = getBorshSchemaForProvingScheme(proofType);
    const serializedProof = borshSerialize(proofSchema, proofJson);
    return serializedProof
}

export function serializePubInputs(pubInputsJson: any, proofType: ProofType) {
    let {vkeySchema, proofSchema , pisSchema } = getBorshSchemaForProvingScheme(proofType);
    const serializedVkey = borshSerialize(pisSchema, pubInputsJson);
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
    if(proofType == ProofType.HALO2_PLONK || proofType == ProofType.HALO2_POSEIDON) {
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

export function deserializeVkey(bytes: Uint8Array,  proofType: ProofType) {
    let {vkeySchema, proofSchema , pisSchema } = getBorshSchemaForProvingScheme(proofType);
    const decodedValue = borshDeserialize(vkeySchema, bytes);
    return decodedValue;
}

export function deserializeProof(bytes: Uint8Array, proofType: ProofType) {
    let {vkeySchema, proofSchema , pisSchema } = getBorshSchemaForProvingScheme(proofType);
    const decodedValue = borshDeserialize(proofSchema, bytes);
    return decodedValue;
}

export function getBorshSchemaForProvingScheme(proofType: ProofType) {
    let vkeySchema;
    let proofSchema;
    let pisSchema;
    switch (proofType) {
        case ProofType.GNARK_GROTH16:
            vkeySchema = getGnarkVKeySchema();
            proofSchema = getGnarkProofSchema();
            pisSchema = getGnarkPubInputsSchema();
            break;
        case ProofType.GROTH16:
            vkeySchema = getSnarkJSVkeySchema();
            proofSchema = getSnarkJSProofSchema();
            pisSchema = getSnarkJSPubInputSchema();
            break;
        case ProofType.HALO2_PLONK:
            vkeySchema = getHaloVKeySchema();
            proofSchema = getHalo2ProofSchema();
            pisSchema = getHalo2PubInputSchema();
            break;
        case ProofType.GNARK_PLONK:
            vkeySchema = getGnarkPlonkVKeySchema();
            proofSchema = getGnarkPlonkProofSchema();
            pisSchema = getGnarkPlonkPubInputsSchema();
            break;
        case ProofType.HALO2_POSEIDON:
            vkeySchema = getHalo2PoseidonVKeySchema();
            proofSchema = getHalo2PoseidonProofSchema();
            pisSchema = getHalo2PoseidonPubInputSchema();
            break;
        case ProofType.PLONKY2:
            vkeySchema = getPlonky2VKeySchema();
            proofSchema = getPlonky2ProofSchema();
            pisSchema = getPlonky2PubInputSchema();
            break;
        default:
            throw new Error("unsupported proof scheme");
    }

    return {vkeySchema, proofSchema, pisSchema}
}