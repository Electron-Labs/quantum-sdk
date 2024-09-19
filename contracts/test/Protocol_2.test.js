const hre = require("hardhat")
const DATA = require("./data/protocol_2.json");
const { deployVerifier } = require("../scripts/deployVerifier");
const { deployProtocol } = require("../scripts/deployProtocol");

describe("Protocol", () => {
  let quantum, protocolContract, protocols, nthProtocol

  before("", async () => {
    protocols = DATA.protocols
    for (let i = 0; i < protocols.length; i++) {
      protocols[i].combinedVkeyHash = Uint8Array.from(protocols[i].combinedVkeyHash)
      protocols[i].pisHash = Uint8Array.from(protocols[i].pisHash)
    }

    const Quantum = await hre.ethers.getContractFactory('lib/Quantum.sol:Quantum');
    quantum = await Quantum.deploy(await deployVerifier(), Uint8Array.from(DATA.oldRoot), Uint8Array.from(DATA.aggVerifierId));
    console.log("quantum deployed at:", await quantum.getAddress())

    protocolContract = await hre.ethers.getContractAt('Protocol', await deployProtocol(protocols[1].combinedVkeyHash));

    nthProtocol = 1
  })

  it("verifySuperproof", async function () {
    let tx, receipt

    // circuit registration
    await quantum.registerProtocol(protocols[0].combinedVkeyHash);
    tx = await quantum.registerProtocol(protocols[1].combinedVkeyHash);
    receipt = await tx.wait()
    console.log("registerProtocol::gasUsed", Number(receipt.gasUsed))

    let treeUpdate = {}
    treeUpdate["newRoot"] = Uint8Array.from(DATA.newRoot)

    tx = await quantum.verifySuperproof(DATA.proof, protocols, treeUpdate);
    receipt = await tx.wait()
    console.log("verifySuperproof::gasUsed", Number(receipt.gasUsed))

    tx = await protocolContract.verifyLatestPubInputs_14(DATA.protocolPubInputs[nthProtocol.toString()]);
    receipt = await tx.wait()
    console.log("verifyPubInputs::gasUsed", Number(receipt.gasUsed))

    let protocolInclusionProof = {}
    protocolInclusionProof["merkleProofPosition"] = DATA.merkleProofPosition
    protocolInclusionProof["merkleProof"] = []
    for (let i = 0; i < DATA.merkleProof.length; i++) {
      protocolInclusionProof["merkleProof"].push(DATA.merkleProof[i])
    }
    protocolInclusionProof["leafNextValue"] = DATA.leafNextValue
    protocolInclusionProof["leafNextIdx"] = DATA.leafNextIdx
    tx = await protocolContract.verifyOldPubInputs_14(protocolInclusionProof, DATA.protocolPubInputs[nthProtocol.toString()]);
    receipt = await tx.wait()
    console.log("verifyPubInputsTreeInclusion::gasUsed", Number(receipt.gasUsed))
  });
});