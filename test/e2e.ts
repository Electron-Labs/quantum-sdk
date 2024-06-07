import { ProofStatus } from "../src/enum/proof_status";
import { ProofType } from "../src/enum/proof_type";
import { Quantum } from "../src/quantum";

const url = "http://3.133.25.95:8000";
async function main() {
    const q = new Quantum(url, "b3047d47c5d6551744680f5c3ba77de90acb84055eefdcbb");
    let r = await q.checkServerConnection();
    console.log(r);

    let circuitHash = await q.registerCircuit("test/dump/gnark/circuit/3/vkey.json", 3, ProofType.GNARK_GROTH16)
    console.log({circuitHash})
    console.log(circuitHash.circuitHash.asString());

    let status = await q.isCircuitRegistered("0x988b45d046b7d24e768e3f2749c2e622c73f958376883edd13704360bb2178c9");
    console.log(status);

    let proofHash = await q.submitProof("test/dump/gnark_2/proof.json", "test/dump/gnark_2/pub_input.json", circuitHash.circuitHash.asString(), ProofType.GNARK_GROTH16);
    console.log(proofHash);

    let proof_status = await q.getProofData("0x55efc9dce7850312afe32f166cf4b3370a3a1544e81386539a5c4a6a2f700aaa");
    console.log(proof_status.proofData);

    let response = await q.getProtocolProof("0x55efc9dce7850312afe32f166cf4b3370a3a1544e81386539a5c4a6a2f700aaa");
    console.log({response});
}   

main().then(() => {
    console.log("done");
})
