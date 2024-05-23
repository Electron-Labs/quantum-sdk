import { ProofType } from "../src/enum/proof_type";
import { Quantum } from "../src/quantum";

const url = "http://127.0.0.1:8000";
async function main() {
    const q = new Quantum(url);
    let r = await q.checkServerConnection();
    console.log(r);

    let circuitHash = await q.registerCircuit("test/dump/gnark_2/vkey.json", 2, ProofType.GNARK_GROTH16)
    console.log(circuitHash.asString());

    let status = await q.isCircuitRegistered(circuitHash);
    console.log(status);

    let proof_id = await q.submitProof("test/dump/gnark_2/proof.json", "test/dump/gnark_2/pub_input.json", circuitHash, ProofType.GNARK_GROTH16);
    console.log(proof_id);
}   

main().then(() => {
    console.log("done");
})
