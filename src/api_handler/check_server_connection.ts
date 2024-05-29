import axios from "axios";

export async function checkServerConnection(rpcEndPoint: string, authToken: string) {
    const headers = {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${authToken}`,
    };
    try {
        const response = await axios.get(`${rpcEndPoint}/ping`, {headers});
        if(response.status != 200) {
            throw new Error("error in check server connection api");
        }
        return response.data;
    } catch(e) {
        console.log(e);
        throw new Error("error in check server connection api " + JSON.stringify(e));
    }
}