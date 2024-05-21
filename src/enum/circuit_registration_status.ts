export enum CircuitRegistrationStatus {
    IN_PROGRESS = "InProgress",
    Completed = "Completed",
    NOT_PICKED = "NotPicked",
    FAILED = "Failed"
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
        default:
            throw new Error("invalid string for enum CircuitRegistrationStatus");
    }
}