export enum CircuitRegistrationStatus {
    IN_PROGRESS = "InProgress",
    Completed = "Completed",
    NOT_PICKED = "NotPicked",
    FAILED = "Failed",
    SMART_CONTRACT_REGISTRATION_PENDING = "SmartContractRegistrationPending"
}

export function getCircuitRegistrationStatusFromString(value: string) {
    switch(value) {
        case "InProgress" :
            return CircuitRegistrationStatus.IN_PROGRESS;
        case "Completed":
            return CircuitRegistrationStatus.Completed;
        case "NotPicked":
            return CircuitRegistrationStatus.NOT_PICKED;
        case "Failed": 
            return CircuitRegistrationStatus.FAILED;
        case "SmartContractRgistrationPending":
            return CircuitRegistrationStatus.SMART_CONTRACT_REGISTRATION_PENDING;
        default:
            throw new Error("invalid string for enum CircuitRegistrationStatus");
    }
}