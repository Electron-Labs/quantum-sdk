const fq = {struct : {
    X: 'string',
    Y: 'string'
}}

const fq_2 = {struct : {
    A0: 'string',
    A1: 'string'
}}

const fq2 = { struct : {
    X : fq_2,
    Y: fq_2
}}

const gnarkVKey = { struct: {
    G1: { struct: {
        Alpha: fq,
        Beta: fq,
        Delta: fq, 
        K: {array: { type: fq} }
    }},
    G2: {struct: {
        Beta: fq2,
        Delta: fq2,
        Gamma: fq2,
    }},

    CommitmentKey: {struct: {
        G: fq2,
        GRootSigmaNeg: fq2
    }},

    PublicAndCommitmentCommitted: { array: { type : { array : {type: 'u32'}}}},
}};

export function getGnarkVKeySchema() {
    return gnarkVKey;
}