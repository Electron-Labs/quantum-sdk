const hre = require("hardhat")
const DATA = require("./data/verifyPubInputs_2.json")
const { deployQuantum } = require("../scripts/deployQuantum");
const { deployProtocol } = require("../scripts/deployProtocol");

describe("ProtocolVerifier", () => {
  let protocol

  before("", async () => {
    const initState = DATA.state
    quantum = await hre.ethers.getContractAt("Quantum", await deployQuantum(initState))

    const Protocol = await hre.ethers.getContractFactory("Protocol_2");
    protocol = await hre.upgrades.deployProxy(Protocol, [DATA.vKeyHash]);
    await protocol.waitForDeployment();
  })

  it("verifyPubInputs", async function () {
    let protocolInclusionProof = {}
    let merkleProof = DATA.merkleProof
    for (let i = 0; i < merkleProof.length; i++) {
      merkleProof[i] = Uint8Array.from(merkleProof[i])
    }
    protocolInclusionProof["protocolVKeyHash"] = DATA.protocolVKeyHash
    protocolInclusionProof["reductionVKeyHash"] = DATA.reductionVKeyHash
    protocolInclusionProof["leafNextValue"] = DATA.leafNextValue
    protocolInclusionProof["leafNextIdx"] = Uint8Array.from(DATA.leafNextIdx)

    const pubInputs = DATA.pubInputs
    for (let i = 0; i < pubInputs.length; i++) {
      pubInputs[i] = Uint8Array.from(pubInputs[i])
    }
    protocolInclusionProof["pubInputs"] = pubInputs


    protocolInclusionProof["merkleProof"] = merkleProof
    protocolInclusionProof["merkleProofPosition"] = DATA.merkleProofPosition

    const tx = await protocol.verifyPubInputs(protocolInclusionProof);
    const receipt = await tx.wait()
    console.log("gasUsed", Number(receipt.gasUsed))
  });
});