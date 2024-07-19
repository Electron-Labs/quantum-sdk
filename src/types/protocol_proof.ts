export class ProtocolProof {
        public merkleProofPosition: number
        public merkleProof: string[]
        public leafNextValue: string
        public leafNextIndex: string
        public superproof_root: string

        constructor(fields: any) {
            this.merkleProofPosition = fields.merkle_proof_position
            this.merkleProof = fields.merkle_proof
            this.leafNextValue = fields.leaf_next_value
            this.leafNextIndex = fields.leaf_next_index
            this.superproof_root = fields.superproof_root
        }
}