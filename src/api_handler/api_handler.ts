import axios from "axios";

export async function checkServerConnection(rpcEndPoint: string) {
    try {
        console.log(rpcEndPoint);
        const response = await axios.get(`${rpcEndPoint}`);
        if(response.status != 200) {
            throw new Error("error in check server connection api");
        }
        return response.data;
    } catch(e) {
        console.log(e);
        throw new Error("error in check server connection api " + JSON.stringify(e));
    }
}