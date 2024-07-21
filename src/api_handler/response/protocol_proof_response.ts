export class ProtocolProofResponse {

    public protocol_vkey_hash: string
    public reduction_vkey_hash: string
    public merkle_proof_position: number
    public merkle_proof: string[]
    public leaf_next_value: string
    public leaf_next_index: string

    constructor(fields: any) {
        this.protocol_vkey_hash =  fields.protocol_vkey_hash;
        this.reduction_vkey_hash = fields.reduction_vkey_hash
        this.merkle_proof_position = fields.merkle_proof_position
        this.merkle_proof = fields.merkle_proof
        this.leaf_next_value = fields.leaf_next_value
        this.leaf_next_index = fields.leaf_next_index
    }
}