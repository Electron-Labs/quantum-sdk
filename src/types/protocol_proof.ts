export class ProtocolProof {
        public merkleProofPosition: number
        public merkleProof: string[]

        constructor(fields: any) {
            this.merkleProofPosition = fields.merkle_proof_position
            this.merkleProof = fields.merkle_proof
        }
}