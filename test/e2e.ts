import { Quantum } from "../src/quantum";

const url = "http://127.0.0.1:8000";
async function main() {
    const q = new Quantum(url);
    let r = await q.checkServerConnection();
    console.log(r);
}

main().then(() => {
    console.log("done");
})
