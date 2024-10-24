import { ethers } from "ethers";
import { ProofStatus } from "../src/enum/proof_status";
import { ProofType } from "../src/enum/proof_type";
import { Quantum } from "../src/quantum";
import hre from "hardhat"
import { getCombinedVKeyHash } from "../src/quantum_helper";

const url = "http://3.133.25.95:8000";
async function main() {
    const q = new Quantum(url, "b3047d47c5d6551744680f5c3ba77de90acb84055eefdcbb");
    let r = await q.checkServerConnection();
    console.log(r);

    // let circuitHash = await q.registerCircuit("test/dump/gnark/circuit/3/vkey.json", 3, ProofType.GNARK_GROTH16)
    // console.log({circuitHash})
    // console.log(circuitHash.circuitHash.asString());

    // let status = await q.isCircuitRegistered(circuitHash.circuitHash.asString());
    // console.log(status);

    // let proofHash = await q.submitProof("test/dump/gnark/proof/3/1bebc197-9942-49a6-8629-adec0136193b/proof.json", "test/dump/gnark/proof/3/1bebc197-9942-49a6-8629-adec0136193b/pubic.json", circuitHash.circuitHash.asString(), ProofType.GNARK_GROTH16);
    // console.log(proofHash);

    // let proof_status = await q.getProofData("0x55efc9dce7850312afe32f166cf4b3370a3a1544e81386539a5c4a6a2f700aaa");
    // console.log(proof_status.proofData);


    // let combinedVKeyHash = getCombinedVKeyHash("0x5dd6e2c9ccf9746c738d6806882b2304dd0686ff75760fed8040e79fa1059290", "0x4b4b13969117f5b7ed8816572a16a748cfc96491e3170c6f12e1f76470141f82")
    // console.log("combinedVKeyHash", combinedVKeyHash)
    // * contract calling *
    // let protocolProofResponse = await q.getProtocolProof("0x603edbccd841d232108368695e26a1c008499c4bba446fb33ddc37ef9ce818eb");
    // console.log("protocolProofResponse", protocolProofResponse)
    // const abi = [
    //     "function verifyOldPubInputs_2((uint256 merkleProofPosition,bytes32[10] merkleProof,bytes32 leafNextValue,bytes8 leafNextIdx),uint256[2] pubInputs) external",
    //     "function verifyLatestPubInputs_2(uint256[2] pubInputs) external",
    // ];
    // const provider = new ethers.JsonRpcProvider("http://127.0.0.1:8545/")
    // let privateKey = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
    // let wallet = new ethers.Wallet(privateKey, provider);
    // const contract = new ethers.Contract("0x9cfdF6EAb414ae15D18207451ddC617e3eb29Adb", abi, wallet);
    // const pubInputs = ["2518569","1587"]
    // let tx
    // tx = await contract.verifyOldPubInputs_2(protocolProofResponse.protocolProof, pubInputs)
    // await tx.wait()
    // console.log("tx", tx)
    // tx = await contract.verifyLatestPubInputs_2(pubInputs)
    // await tx.wait()
    // console.log("tx", tx)
}

main().then(() => {
    console.log("done");
})
