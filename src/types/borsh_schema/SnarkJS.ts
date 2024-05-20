const nestedArrayOfStringType = { array: { type : { array : {type: 'string'}}}}

const snarkJSVkey = {struct : {
    protocol : 'string',
    curve: 'string',
    nPublic: 'u32',
    vk_alpha_1 : { array: { type: 'string'}},
    vk_beta_2 : nestedArrayOfStringType,
    vk_gamma_2: nestedArrayOfStringType,
    vk_delta_2: nestedArrayOfStringType,
    vk_alphabeta_12: { array : {type: nestedArrayOfStringType } },
    IC: nestedArrayOfStringType
}}

export function getSnarkJSVkeySchema() {
    return snarkJSVkey;
}