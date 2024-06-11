const hre = require("hardhat")
const DATA = require("./data/verifyPubInputs_2.json")
const { deployQuantum } = require("../scripts/deployQuantum");
const { deployProtocol } = require("../scripts/deployProtocol");

describe("ProtocolVerifier", () => {
  let protocol

  before("", async () => {
    const initState = DATA.state
    quantum = await hre.ethers.getContractAt("Quantum", await deployQuantum(initState))

    protocol = await hre.ethers.getContractAt("Protocol", await deployProtocol(DATA.vKeyHash));
  })

  it("verifyPubInputs", async function () {
    let quantumProof = {}
    let merkleProof = DATA.merkleProof
    for (let i = 0; i < merkleProof.length; i++) {
      merkleProof[i] = hre.ethers.getBytes(Uint8Array.from(merkleProof[i]))
    }
    quantumProof["protocolVKeyHash"] = DATA.protocolVKeyHash
    quantumProof["reductionVKeyHash"] = DATA.reductionVKeyHash
    quantumProof["leafNextValue"] = DATA.leafNextValue
    quantumProof["leafNextIdx"] = hre.ethers.getBytes(Uint8Array.from(DATA.leafNextIdx))

    const pubInputs = DATA.pubInputs
    for (let i = 0; i < pubInputs.length; i++) {
      pubInputs[i] = hre.ethers.getBytes(Uint8Array.from(pubInputs[i]))
    }
    quantumProof["pubInputs"] = pubInputs


    quantumProof["merkleProof"] = merkleProof
    quantumProof["merkleProofPosition"] = DATA.merkleProofPosition

    const tx = await protocol.verifyPubInputs(quantumProof);
    const receipt = await tx.wait()
    console.log("gasUsed", Number(receipt.gasUsed))
  });
});