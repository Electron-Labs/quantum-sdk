const hre = require("hardhat")
const DATA = require("./data/protocol_2.json");
const { deployVerifier } = require("../scripts/deployVerifier");
const { deployProtocol } = require("../scripts/deployProtocol");

describe("Protocol", () => {
  let quantum, protocolContract, nthProtocol

  before("", async () => {
    const Quantum = await hre.ethers.getContractFactory('lib/Quantum.sol:Quantum');
    quantum = await Quantum.deploy(await deployVerifier(), Uint8Array.from(DATA.aggVerifierId));
    console.log("quantum deployed at:", await quantum.getAddress())

    nthProtocol = 1

    // protocolContract = await hre.ethers.getContractAt('Protocol', await deployProtocol(Uint8Array.from(DATA.protocols[nthProtocol].combinedVkeyHash)));
  })

  it("verifySuperproof and verifyPubInputs", async function () {
    let tx, receipt

    tx = await quantum.verifySuperproof(DATA.proof, Uint8Array.from(DATA.batchRoot));
    receipt = await tx.wait()
    console.log("verifySuperproof::gasUsed", Number(receipt.gasUsed))

    // tx = await protocolContract.verifyPubInputs_14(DATA.protocolPubInputs[nthProtocol.toString()], DATA.merkleProofPosition, DATA.merkleProof);
    // receipt = await tx.wait()
    // console.log("verifyPubInputsTreeInclusion::gasUsed", Number(receipt.gasUsed))
  });
});