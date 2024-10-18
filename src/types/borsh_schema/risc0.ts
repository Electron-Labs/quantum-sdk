const risc0VkeySchema = {struct: {
    vkey_bytes: {array: {type: 'u32', len: 8}},
}}

const risc0ProofSchema = {struct: { 
    proof_bytes: {array: {type: 'u8'}}
    }
}

const risc0PisSchema = {array: {type: 'string'}};

export function getRisc0VKeySchema() {
    return risc0VkeySchema;
}

export function getRisc0ProofSchema() {
    return risc0ProofSchema;
}

export function getRisc0PubInputSchema() {
    return risc0PisSchema
}
