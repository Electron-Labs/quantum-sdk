import { ProofType } from "../src/enum/proof_type";
import { Quantum } from "../src/quantum";

const url = "http://127.0.0.1:8000";
async function main() {
    const q = new Quantum(url);
    let r = await q.checkServerConnection();
    console.log(r);

    let circuitHash = await q.registerCircuit("test/dump/vkey.json", 2, ProofType.GNARK_GROTH16)
    console.log(circuitHash.asString());
}

main().then(() => {
    console.log("done");
})
