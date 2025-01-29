import { ethers } from "ethers";
import { ProofStatus } from "../src/enum/proof_status";
import { ProofType } from "../src/enum/proof_type";
import { Quantum } from "../src/quantum";
import hre from "hardhat"
import { getCombinedVKeyHash } from "../src/quantum_helper";

const url = "";
async function main() {
    // const q = new Quantum(url, "");
    // let r = await q.checkServerConnection();
    // console.log(r);

    // let combinedVKeyHash = getCombinedVKeyHash("0xfda4c5da65309e9a7e6541858b589626a4dacb6381bb861e20d2be569f3ab934", "0x00a333a9830fb7acc5dd94e7af1625e0f3d27193c1dea79a9403b5eaa173d95f")
    // console.log("combinedVKeyHash", combinedVKeyHash)
    // * contract calling *
    // let protocolProofResponse = await q.getProtocolProof("0xe64878cbec29153c24632af86d91631dd9448cab74df424281fa41490f004484");
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
