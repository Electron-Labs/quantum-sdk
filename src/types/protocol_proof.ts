export class ProtocolProof {
        public merkleProofPosition: number
        public merkleProof: string[]
        public leafNextValue: string
        public leafNextIdx: string

        constructor(fields: any) {
            this.merkleProofPosition = fields.merkle_proof_position
            this.merkleProof = fields.merkle_proof
            this.leafNextValue = fields.leaf_next_value
            this.leafNextIdx = fields.leaf_next_index
        }
}