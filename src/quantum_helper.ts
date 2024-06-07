import { ProofDataResponse } from "./api_handler/response/proof_data_response";
import { ProtocolProofResponse } from "./api_handler/response/protocol_proof_response";
import { getProofStatusFromString } from "./enum/proof_status";
import { ProofType } from "./enum/proof_type";
import { getGnarkPubInputsSchema, getGnarkVKeySchema, serializeGnarkProof } from "./types/borsh_schema/gnark";
import { getSnarkJSPubInputSchema, getSnarkJSVkeySchema, serializeSnarkProof } from "./types/borsh_schema/SnarkJS";
import { ContractAddress } from "./types/contract";
import { Keccak256Hash } from "./types/keccak256_hash";
import { ProofData } from "./types/proof_status";
import { ProtocolProof } from "./types/protocol_proof";
import { borshSerialize } from "./utils/borsh";

export function getProtocolProofFromResponse(resp: ProtocolProofResponse) {
    return new ProtocolProof({proof: resp.proof, proofHelper: resp.proof_helper})
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
    }
    const serializedVkey= borshSerialize(vkeySchema, vkeyJson);
    return serializedVkey;
}

// TODO: handle this serialize based on proving schemes in better way
export function serializeProof(proofJson: any, proofType: ProofType) {
    if (proofType == ProofType.GNARK_GROTH16) {
        return serializeGnarkProof(proofJson);
    } else if (proofType == ProofType.GROTH16) {
        return serializeSnarkProof(proofJson);
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
    }
    const serializedVkey= borshSerialize(pubInputsSchema, pubInputsJson);
    return serializedVkey;
}
