const sp1VkeySchema = {struct: {
    vkey_bytes: {array: {type: 'u8'}},
}}

const sp1ProofSchema = {struct: { 
    proof_bytes: {array: {type: 'u8'}}
    }
}

const sp1PisSchema = {array: {type: 'string'}};

export function getSp1VKeySchema() {
    return sp1VkeySchema;
}

export function getSp1ProofSchema() {
    return sp1ProofSchema;
}

export function getSp1PubInputSchema() {
    return sp1PisSchema
}
