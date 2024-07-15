const hre = require("hardhat")
const DATA = require("./data/protocol_4.json");
const { deployProtocol } = require("../scripts/deployProtocol");

describe("Protocol", () => {
  let quantum, protocolContract, vkHashes, protocolPisHashes, n

  before("", async () => {
    n = 4

    vkHashes = DATA.vkHashes
    protocolPisHashes = DATA.protocolPisHashes
    for (let i = 0; i < vkHashes.length; i++) {
      vkHashes[i] = Uint8Array.from(vkHashes[i])
      protocolPisHashes[i] = Uint8Array.from(protocolPisHashes[i])
    }

    const Verifier = await hre.ethers.getContractFactory("lib/Verifier_4.sol:Verifier");
    const verifier = await hre.upgrades.deployProxy(Verifier);
    await verifier.waitForDeployment();

    const Quantum = await hre.ethers.getContractFactory('lib/Quantum_*.sol:Quantum_4');
    quantum = await Quantum.deploy(await verifier.getAddress(), Uint8Array.from(DATA.oldRoot));
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

    let treeUpdate = {}
    treeUpdate["newRoot"] = Uint8Array.from(DATA.newRoot)

    tx = await quantum.verifySuperproof(DATA.proof, batch, treeUpdate);
    receipt = await tx.wait()
    console.log("verifySuperproof::gasUsed", Number(receipt.gasUsed))

    // const pubInputs = [243542, 494]
    // tx = await protocolContract.verifyPubInputs_2(pubInputs);
    // receipt = await tx.wait()
    // console.log("verifyPubInputs::gasUsed", Number(receipt.gasUsed))
  });
});