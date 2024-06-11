const hre = require("hardhat")
const { deployQuantum } = require("../scripts/deployQuantum");
const DATA = require("./data/verifyPubInputs_4.json");
const { Quantum } = require("../../");

describe("ProtocolVerifier_4", () => {
  let protocol, quantum

  before("", async () => {
    quantum = await hre.ethers.getContractAt("Quantum", await deployQuantum(DATA.state))
    const Protocol = await hre.ethers.getContractFactory("Protocol_4");
    protocol = await hre.upgrades.deployProxy(Protocol, [DATA.vKeyHash]);
    await protocol.waitForDeployment();
  })

  it("verifyPubInputs", async function () {
    let quantumProof = {}
    quantumProof["protocolVKeyHash"] = DATA.protocolVKeyHash
    quantumProof["reductionVKeyHash"] = DATA.reductionVKeyHash
    quantumProof["leafNextValue"] = DATA.leafNextValue
    quantumProof["leafNextIdx"] = DATA.leafNextIdx

    const pubInputs = DATA.pubInputs
    for (let i = 0; i < pubInputs.length; i++) {
      pubInputs[i] = Uint8Array.from(pubInputs[i])
    }
    quantumProof["pubInputs"] = pubInputs

    quantumProof["merkleProof"] = DATA.merkleProof
    quantumProof["merkleProofPosition"] = DATA.merkleProofPosition

    const tx = await protocol.verifyPubInputs(quantumProof);
    const receipt = await tx.wait()
    console.log("gasUsed", Number(receipt.gasUsed))
  });
});