const hre = require("hardhat")
const DATA = require("./data/protocol_10.json");
const { deployProtocol } = require("../scripts/deployProtocol");
const { deployVerifier } = require("../scripts/deployVerifier");

describe("Protocol", () => {
  let quantum, protocolContract, vkHashes, protocolPisHashes, n

  before("", async () => {
    n = 10

    vkHashes = DATA.vkHashes
    protocolPisHashes = DATA.protocolPisHashes
    for (let i = 0; i < vkHashes.length; i++) {
      vkHashes[i] = Uint8Array.from(vkHashes[i])
      protocolPisHashes[i] = Uint8Array.from(protocolPisHashes[i])
    }

    const Quantum = await hre.ethers.getContractFactory('lib/Quantum.sol:Quantum');
    quantum = await Quantum.deploy(await deployVerifier());
    console.log("quantum deployed at:", await quantum.getAddress())

    protocolContract = await hre.ethers.getContractAt('Protocol', await deployProtocol(vkHashes[0]));
  })

  it("verifySuperproof", async function () {
    let tx, receipt

    // circuit registration
    await quantum.registerProtocol(vkHashes[0]);
    await quantum.registerProtocol(vkHashes[1]);
    await quantum.registerProtocol(vkHashes[2]);
    tx = await quantum.registerProtocol(vkHashes[3]);
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

    tx = await quantum.verifySuperproof(DATA.proof, batch);
    receipt = await tx.wait()
    console.log("verifySuperproof::gasUsed", Number(receipt.gasUsed))


    const pubInputs = [243542, 494]
    tx = await protocolContract.verifyPubInputs_2(pubInputs);
    receipt = await tx.wait()
    console.log("verifyPubInputs::gasUsed", Number(receipt.gasUsed))
  });
});