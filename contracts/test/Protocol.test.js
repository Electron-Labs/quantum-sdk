const hre = require("hardhat")
const { upgrades } = require("hardhat")
const DATA = require("./data/protocol.json");
const { deployVerifier } = require("../scripts/deployVerifier");

describe("Protocol", () => {
  let quantum, protocolRisc0Contract, protocolSp1Contract

  before("", async () => {
    const Quantum = await hre.ethers.getContractFactory('lib/Quantum.sol:Quantum');
    quantum = await upgrades.deployProxy(Quantum, [await deployVerifier(), Uint8Array.from(DATA.aggVKey)], { kind: 'uups' })

    console.log("quantum deployed at:", await quantum.getAddress())

    const ProtocolRisc0 = await hre.ethers.getContractFactory('lib/ProtocolRisc0.sol:Protocol');
    protocolRisc0Contract = await ProtocolRisc0.deploy(DATA.risc0Agg.vKeyHash);

    const ProtocolSp1 = await hre.ethers.getContractFactory('lib/ProtocolSp1.sol:Protocol');
    protocolSp1Contract = await ProtocolSp1.deploy(DATA.sp1Agg.vKeyHash);
  })

  it("verifySuperproof and verifyPubInputs", async function () {
    let tx, receipt

    tx = await quantum.verifySuperproof(DATA.proof, Uint8Array.from(DATA.superRoot));
    receipt = await tx.wait()
    console.log("verifySuperproof::gasUsed", Number(receipt.gasUsed))

    // risc0 protocol
    tx = await protocolRisc0Contract.verifyPubInputs_2(DATA.risc0Agg.publicInputs, DATA.risc0Agg.merkleProofPosition, DATA.risc0Agg.merkleProof);
    receipt = await tx.wait()
    console.log("risc0 verifyPubInputs_2::gasUsed", Number(receipt.gasUsed))

    // sp1 protocol
    const merkleProof = {"position": DATA.sp1Agg.merkleProofPosition, "proof": DATA.sp1Agg.merkleProof}
    tx = await protocolSp1Contract.verifyPubInputs(merkleProof, Uint8Array.from(DATA.sp1Agg.publicInputs));
    receipt = await tx.wait()
    console.log("sp1 verifyPubInputs::gasUsed", Number(receipt.gasUsed))
  });
});
