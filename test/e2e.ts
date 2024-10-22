import { ethers } from "ethers";
import { ProofStatus } from "../src/enum/proof_status";
import { ProofType } from "../src/enum/proof_type";
import { Quantum } from "../src/quantum";
import hre from "hardhat"
import { getCombinedVKeyHash } from "../src/quantum_helper";

const url = "http://localhost:8000";
async function main() {
    const q = new Quantum(url, "GnarkGroth16");
    let r = await q.checkServerConnection();
    console.log(r);

    // let circuitHash = await q.registerGnarkGroth16Circuit("/home/ubuntu/quantum-risc0-circuits/host_gnark_groth16/vk.bin")
    // console.log({circuitHash})
    // console.log(circuitHash.circuitHash.asString());

    // circuitHash = await q.registerGnarkPlonkCircuit("/home/ubuntu/quantum-risc0-circuits/host_gnark_plonk/vk.bin")
    // console.log({circuitHash})
    // console.log(circuitHash.circuitHash.asString());

    // let circuit_hash = await q.registerHalo2PlonkCircuit("/home/ubuntu/Spectre/build/sg2.json","/home/ubuntu/Spectre/build//protocol.json");
    // console.log({circuit_hash})
    // console.log(circuit_hash.circuitHash.asString());

    // let circuitHash = await q.registerSnarkJSGroth16Circuit("/home/ubuntu/aditya-risc0-test/quantum-sdk/test/dump/snark/circuit/2/vkey.json")
    // console.log({circuitHash})
    // console.log(circuitHash.circuitHash.asString());

    // let circuitHash = await q.registerHalo2PoseidonCircuit("/home/ubuntu/utkarsh_pg/risc0_test/host_halo2_kzg_poseidon/sg2.json", "/home/ubuntu/utkarsh_pg/risc0_test/host_halo2_kzg_poseidon/protocol.json")
    // console.log({circuitHash})
    // console.log(circuitHash.circuitHash.asString());

    // let circuitHash = await q.registerPlonky2Circuit("/home/ubuntu/utkarsh_pg/risc0_test/host_plonky2/src/common_bytes.bin", "/home/ubuntu/utkarsh_pg/risc0_test/host_plonky2/src/verifier_bytes.bin");
    // console.log({circuitHash})
    // console.log(circuitHash.circuitHash.asString());

    // let circuitHash = await q.registerRisc0Circuit("/home/ubuntu/utkarsh_pg/risc0_test/host_risc0/image_id.json");
    // console.log({circuitHash})
    // console.log(circuitHash.circuitHash.asString());

    // let circuitHash = await q.registerSp1Circuit("/home/ubuntu/utkarsh_pg/risc0_test/host_sp1/vk");
    // console.log({circuitHash})
    // console.log(circuitHash.circuitHash.asString());

    // let status = await q.isCircuitRegistered("0xceeb414032c1ce1d0d9e8627bf132e49c6e528f2c60c8c8d12890d99ffdaecc3");
    // console.log(status);

    // let proofHash = await q.submitGnarkGroth16Proof("/home/ubuntu/quantum-risc0-circuits/host_gnark_groth16/proof.bin", "/home/ubuntu/quantum-risc0-circuits/host_gnark_groth16/pis.json", '0xd7a7bc7f5edfd20da23641577e8fb092587f8a53014725920b2eb084b4630f9e');
    // console.log(proofHash);

    // let proofHash = await q.submitHalo2PlonkProof("/home/ubuntu/Spectre/build/proof.bin", "/home/ubuntu/Spectre/build/instances.json", '0x47a6a69132ba315d49999dfda42cb9c0d4637ea41415943ae87c7635f6da8d14');
    // console.log(proofHash);

    // let proofHash = await q.submitGnarkPlonkProof("/home/ubuntu/quantum-risc0-circuits/host_gnark_plonk/proof.bin", "/home/ubuntu/quantum-risc0-circuits/host_gnark_plonk/pis.json", '0x8adb1656b0ab24267491a7af3efae5bc42964ec3a8ec6ad968668e9bb682e753');
    // console.log(proofHash);

    // let proofHash = await q.submitSnarkJSGroth16Proof("/home/ubuntu/aditya-risc0-test/quantum-sdk/test/dump/snark/proof/2/166adf40-7545-4d17-b99d-f80fe9555e4f/proof.json", "/home/ubuntu/aditya-risc0-test/quantum-sdk/test/dump/snark/proof/2/166adf40-7545-4d17-b99d-f80fe9555e4f/public.json", '0xceeb414032c1ce1d0d9e8627bf132e49c6e528f2c60c8c8d12890d99ffdaecc3');
    // console.log(proofHash);

    // let proofHash = await q.submitPlonky2Proof("/home/ubuntu/utkarsh_pg/risc0_test/host_plonky2/src/proof_bytes.bin", '0xd1571b92c7ba27a64e9f2c29662cc9e3329ba9694f62063b4723f8134612412b');
    // console.log(proofHash);

    // let proofHash = await q.submitRisc0Proof("/home/ubuntu/utkarsh_pg/risc0_test/host_risc0/receipt", '0x92271d368782d86f4367610307a0e3d6e5b4039206f20b7636972259656409a8');
    // console.log(proofHash);

    //  let proofHash = await q.submitSp1Proof("/home/ubuntu/utkarsh_pg/risc0_test/host_sp1/proof", '0x8460624ba6c0eedaedf079289dd488a2680bbc6e60a546e8465e932f147ffeb7');
    // console.log(proofHash);

    // let proofHash = await q.submitHalo2PoseidonProof("/home/ubuntu/utkarsh_pg/risc0_test/host_halo2_kzg_poseidon/proof.bin", "/home/ubuntu/utkarsh_pg/risc0_test/host_halo2_kzg_poseidon/instances.json", '0x91add0bd41d178cbe947daaa4eae315355715b6dd6d518f92c5f139d02853ef3');
    // console.log(proofHash);

    // let proof_status = await q.getProofData("0xb50ea463d922cc7aad3d1e420782f412a44d80039cb915e89d45189469e1be6b");
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
