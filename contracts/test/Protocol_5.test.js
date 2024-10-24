const hre = require("hardhat")
const { upgrades } = require("hardhat")
const DATA = require("./data/protocol_5.json");
const { deployVerifier } = require("../scripts/deployVerifier");
const { deployProtocol } = require("../scripts/deployProtocol");

describe("Protocol", () => {
  let quantum, protocolContract

  before("", async () => {
    const Quantum = await hre.ethers.getContractFactory('lib/Quantum.sol:Quantum');
    quantum = await upgrades.deployProxy(Quantum, [await deployVerifier(), Uint8Array.from(DATA.aggVerifierId)], { kind: 'uups' })

    console.log("quantum deployed at:", await quantum.getAddress())

    protocolContract = await hre.ethers.getContractAt('Protocol', await deployProtocol(DATA.combinedVKeyHash));
  })

  it("verifySuperproof and verifyPubInputs", async function () {
    let tx, receipt

    tx = await quantum.verifySuperproof(DATA.proof, Uint8Array.from(DATA.superRoot));
    receipt = await tx.wait()
    console.log("verifySuperproof::gasUsed", Number(receipt.gasUsed))

    tx = await protocolContract.verifyPubInputs_5(DATA.protocolPubInputs, DATA.merkleProofPosition, DATA.merkleProof);
    receipt = await tx.wait()
    console.log("verifyPubInputsTreeInclusion::gasUsed", Number(receipt.gasUsed))
  });
});