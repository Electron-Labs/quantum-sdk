const hre = require("hardhat")
const DATA = require("./data/protocol_20.json");
const { deployProtocol } = require("../scripts/deployProtocol");
const { deployVerifier } = require("../scripts/deployVerifier");

describe("Protocol", () => {
  let quantum, protocolContract, vkHashes, protocolPisHashes, n

  before("", async () => {
    n = 20

    vkHashes = DATA.vkHashes
    protocolPisHashes = DATA.protocolPisHashes
    for (let i = 0; i < vkHashes.length; i++) {
      vkHashes[i] = Uint8Array.from(vkHashes[i])
      protocolPisHashes[i] = Uint8Array.from(protocolPisHashes[i])
    }

    const Quantum = await hre.ethers.getContractFactory('lib/Quantum.sol:Quantum');
    quantum = await Quantum.deploy(await deployVerifier(), Uint8Array.from(DATA.oldRoot));
    console.log("quantum deployed at:", await quantum.getAddress())

    protocolContract = await hre.ethers.getContractAt('Protocol', await deployProtocol(vkHashes[0]));
  })

  it("verifySuperproof", async function () {
    let tx, receipt

    // circuit registration
    for (let i = 0; i < n - 1; i++) {
      await quantum.registerProtocol(vkHashes[i]);
    }
    tx = await quantum.registerProtocol(vkHashes[n - 1]);
    receipt = await tx.wait()
    console.log("registerProtocol::gasUsed", Number(receipt.gasUsed))

    let batch = {}
    batch["protocols"] = []
    for (let i = 0; i < n; i++) {
      let protocol = {}
      protocol["vkHash"] = vkHashes[i]
      protocol["pubInputsHash"] = protocolPisHashes[i]
      batch["protocols"].push(protocol)
    }

    let treeUpdate = {}
    treeUpdate["newRoot"] = Uint8Array.from(DATA.newRoot)

    let protocolInclusionProof = {}
    protocolInclusionProof["merkleProofPosition"] = DATA.merkleProofPosition
    protocolInclusionProof["merkleProof"] = []
    for (let i = 0; i < DATA.merkleProof.length; i++) {
      protocolInclusionProof["merkleProof"].push(DATA.merkleProof[i])
    }
    protocolInclusionProof["leafNextValue"] = DATA.leafNextValue
    protocolInclusionProof["leafNextIdx"] = DATA.leafNextIdx

    tx = await quantum.verifySuperproof(DATA.proof, batch, treeUpdate);
    receipt = await tx.wait()
    console.log("verifySuperproof::gasUsed", Number(receipt.gasUsed))


    tx = await protocolContract.verifyLatestPubInputs_5(DATA.protocolPubInputs["0"]);
    receipt = await tx.wait()
    console.log("verifyPubInputs::gasUsed", Number(receipt.gasUsed))

    tx = await protocolContract.verifyOldPubInputs_5(protocolInclusionProof, DATA.protocolPubInputs["0"]);
    receipt = await tx.wait()
    console.log("verifyPubInputsTreeInclusion::gasUsed", Number(receipt.gasUsed))
  });
});