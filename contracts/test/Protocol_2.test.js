const hre = require("hardhat")
const DATA = require("./data/protocol_2.json");
const { deployVerifier } = require("../scripts/deployVerifier");
// const { deployProtocol } = require("../scripts/deployProtocol");

describe("Protocol", () => {
  let quantum, protocolContract, protocols

  before("", async () => {
    protocols = DATA.protocols
    for (let i = 0; i < protocols.length; i++) {
      protocols[i].combinedVkeyHash = Uint8Array.from(protocols[i].combinedVkeyHash)
      protocols[i].pisHash = Uint8Array.from(protocols[i].pisHash)
    }

    const Quantum = await hre.ethers.getContractFactory('lib/Quantum.sol:Quantum');
    quantum = await Quantum.deploy(await deployVerifier(), Uint8Array.from(DATA.oldRoot), Uint8Array.from(DATA.aggVerifierId));
    console.log("quantum deployed at:", await quantum.getAddress())

    // protocolContract = await hre.ethers.getContractAt('Protocol', await deployProtocol(vkHashes[0]));
  })

  it("verifySuperproof", async function () {
    let tx, receipt

    // circuit registration
    await quantum.registerProtocol(protocols[0].combinedVkeyHash);
    tx = await quantum.registerProtocol(protocols[1].combinedVkeyHash);
    receipt = await tx.wait()
    console.log("registerProtocol::gasUsed", Number(receipt.gasUsed))


    let batch = {}
    batch["protocols"] = protocols

    let treeUpdate = {}
    treeUpdate["newRoot"] = Uint8Array.from(DATA.newRoot)

    tx = await quantum.verifySuperproof(DATA.proof, protocols, treeUpdate);
    receipt = await tx.wait()
    console.log("verifySuperproof::gasUsed", Number(receipt.gasUsed))

    // const pubInputs = ["1482", "1482"]
    // tx = await protocolContract.verifyLatestPubInputs_2(pubInputs);
    // receipt = await tx.wait()
    // console.log("verifyPubInputs::gasUsed", Number(receipt.gasUsed))
  });
});