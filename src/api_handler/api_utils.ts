export function getRequestheader(authToken: string) {
    const headers = {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${authToken}`,
    };
    return headers
}