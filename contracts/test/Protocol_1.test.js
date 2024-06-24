const hre = require("hardhat")
const DATA = require("./data/protocol.json");

describe("Protocol", () => {
  let quantum, protocolContract, vkHashes, protocolPisHashes, n

  before("", async () => {
    n = 1

    vkHashes = DATA.vkHashes
    protocolPisHashes = DATA.protocolPisHashes
    for (let i = 0; i < vkHashes.length; i++) {
      vkHashes[i] = Uint8Array.from(vkHashes[i])
      protocolPisHashes[i] = Uint8Array.from(protocolPisHashes[i])
    }

    const Verifier = await hre.ethers.getContractFactory("lib/Verifier_1.sol:Verifier");
    const verifier = await hre.upgrades.deployProxy(Verifier);
    await verifier.waitForDeployment();

    const Quantum = await hre.ethers.getContractFactory('lib/Quantum.sol:Quantum_1');
    quantum = await Quantum.deploy(await verifier.getAddress());
    console.log("quantum deployed at:", await quantum.getAddress())

    const Protocol = await hre.ethers.getContractFactory('lib/Protocol.sol:Protocol_4');
    protocolContract = await Protocol.deploy(vkHashes[0]);
  })

  it("verifySuperproof", async function () {
    let tx, receipt

    // circuit registration
    tx = await quantum.registerProtocol(vkHashes[0]);
    // await quantum.registerProtocol(vkHashes[2]);
    // await quantum.registerProtocol(vkHashes[6]);
    // tx = await quantum.registerProtocol(vkHashes[7]);
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

    // batch["protocols"][0]["pubInputsHash"] = "0xc7097c499dc5ab8144fb8fc0b5f3d6df062dae105e17ee7cbab77be75cd13714"
    tx = await quantum.verifySuperproof(DATA.proof, batch);
    receipt = await tx.wait()
    console.log("verifySuperproof::gasUsed", Number(receipt.gasUsed))


    const pubInputs = ["2496000", "40", "40", "40"]
    tx = await protocolContract.verifyPubInputs(pubInputs);
    receipt = await tx.wait()
    console.log("verifyPubInputs::gasUsed", Number(receipt.gasUsed))
  });
});