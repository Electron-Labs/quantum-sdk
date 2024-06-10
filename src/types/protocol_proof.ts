export class ProtocolProof {

        public protocolVkeyHash: string
        public reductionVkeyHash: string
        public merkleProofPosition: number[]
        public merkleProof: number[][]
        public leafNextValue: string
        public leafNextIndex: number[]
    
        constructor(fields: any) {
            this.protocolVkeyHash =  fields.protocol_vkey_hash;
            this.reductionVkeyHash = fields.reduction_vkey_hash
            this.merkleProofPosition = fields.merkle_proof_position
            this.merkleProof = fields.merkle_proof
            this.leafNextValue = fields.leaf_next_value
            this.leafNextIndex = fields.leaf_next_index
        }
}