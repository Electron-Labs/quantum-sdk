import { ethers } from "ethers";
import { ProofStatus } from "../src/enum/proof_status";
import { ProofType } from "../src/enum/proof_type";
import { Quantum } from "../src/quantum";
import hre from "hardhat"

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


    // * contract calling *
    // let protocolProofResponse = await q.getProtocolProof("0xfa6df811a48f4a3f6966545cf1c914295146a707dc84e5a1c1c39b6b485d2d2a");
    // console.log({protocolProofResponse});
//     const abi = [
//         "function verifyPubInputs((bytes32 protocolVKeyHash,bytes32 reductionVKeyHash,uint256 merkleProofPosition,bytes32[10] merkleProof,bytes32 leafNextValue,bytes8 leafNextIdx,bytes32[4] pubInputs)) external",
//     ];
//     const provider = new ethers.JsonRpcProvider("http://127.0.0.1:8545/")
//     let privateKey = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
//     let wallet = new ethers.Wallet(privateKey, provider);
//     const contract = new ethers.Contract("0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9", abi, wallet);
//     const pubInputs = ["4", "4", "4", "3"]
//     const protocolInclusionProof = q.getProtocolInclusionProof(protocolProofResponse.protocolProof, pubInputs)
//     let tx = await contract.verifyPubInputs(protocolInclusionProof)
//     console.log("tx", tx)
}

main().then(() => {
    console.log("done");
})
