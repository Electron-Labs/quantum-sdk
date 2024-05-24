export enum ProofStatus {
    NOT_FOUND = 1,
    REGISTERED = 2,
    REDUCING = 3,
    REDUCED = 4,
    AGGREGATING = 5,
    AGGREGATED = 6,
    VERIFIED = 7,
    REDUCTION_FAILED = 8,
    AGGREGATION_FAILED = 9,
}


export function getProofStatusFromString(value: string) {
    switch(value) {
        case "NotFound" :
            return ProofStatus.NOT_FOUND;
        case "Registered":
            return ProofStatus.REGISTERED;
        case "Reducing":
            return ProofStatus.REDUCING;
        case "Reduced": 
            return ProofStatus.REDUCED;
        case "Aggregating": 
            return ProofStatus.AGGREGATING;
        case "Aggregated": 
            return ProofStatus.AGGREGATED;
        case "Verified": 
            return ProofStatus.VERIFIED;
        case "ReductionFailed": 
            return ProofStatus.REDUCTION_FAILED;
        case "AggregationFailed": 
            return ProofStatus.AGGREGATION_FAILED;
        default:
            throw new Error("invalid string for enum ProofStatus");
    }
}