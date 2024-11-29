const hre = require("hardhat")
const { upgrades } = require("hardhat")
const DATA = require("./data/protocol.json");
const { deployVerifier } = require("../scripts/deployVerifier");

describe("Protocol", () => {
  let quantum, protocol1Contract, protocol2Contract

  before("", async () => {
    const Quantum = await hre.ethers.getContractFactory('lib/Quantum.sol:Quantum');
    quantum = await upgrades.deployProxy(Quantum, [await deployVerifier(), Uint8Array.from(DATA.aggVKey)], { kind: 'uups' })

    console.log("quantum deployed at:", await quantum.getAddress())

    const Protocol1 = await hre.ethers.getContractFactory('lib/example_protocol/Protocol1.sol:Protocol');
    protocol1Contract = await Protocol1.deploy(DATA.risc0Agg.vKeyHash);

    const Protocol2 = await hre.ethers.getContractFactory('lib/example_protocol/Protocol2.sol:Protocol');
    protocol2Contract = await Protocol2.deploy(DATA.sp1Agg.vKeyHash);
  })

  it("verifySuperproof and verifyPubInputs", async function () {
    let tx, receipt

    tx = await quantum.verifySuperproof(DATA.proof, Uint8Array.from(DATA.superRoot));
    receipt = await tx.wait()
    console.log("verifySuperproof::gasUsed", Number(receipt.gasUsed))

    // risc0 protocol
    tx = await protocol1Contract.verifyPubInputs(DATA.risc0Agg.publicInputs, DATA.risc0Agg.merkleProofPosition, DATA.risc0Agg.merkleProof);
    receipt = await tx.wait()
    console.log("risc0 verifyPubInputs::gasUsed", Number(receipt.gasUsed))

    // sp1 protocol
    const merkleProof = {"position": DATA.sp1Agg.merkleProofPosition, "proof": DATA.sp1Agg.merkleProof}
    tx = await protocol2Contract.verifyPubInputs(merkleProof, Uint8Array.from(DATA.sp1Agg.publicInputs));
    receipt = await tx.wait()
    console.log("sp1 verifyPubInputs::gasUsed", Number(receipt.gasUsed))
  });
});
