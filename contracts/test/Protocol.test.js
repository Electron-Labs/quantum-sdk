const hre = require("hardhat")
const { upgrades } = require("hardhat")
const DATA = require("./data/protocol.json");
const { deployVerifier } = require("../scripts/deployVerifier");

describe("Protocol", () => {
  let quantum, aggregateVerifierContract

  before("", async () => {
    const Quantum = await hre.ethers.getContractFactory('lib/Quantum.sol:Quantum');
    quantum = await upgrades.deployProxy(Quantum, [await deployVerifier(), Uint8Array.from(DATA.aggVKey)], { kind: 'uups' })

    console.log("quantum deployed at:", await quantum.getAddress())

    const AggregateVerifier = await hre.ethers.getContractFactory('lib/AggregateVerifier.sol:AggregateVerifier');
    aggregateVerifierContract = await AggregateVerifier.deploy();
  })

  it("verifySuperproof and verifyPubInputs", async function () {
    let tx, receipt, merkleProof

    tx = await quantum.verifySuperproof(DATA.proof, Uint8Array.from(DATA.superRoot));
    receipt = await tx.wait()
    // console.log("verifySuperproof::gasUsed", Number(receipt.gasUsed))

    // risc0 aggregate
    merkleProof = {"position": DATA.risc0Agg.merkleProofPosition, "elms": DATA.risc0Agg.merkleProof}
    tx = await aggregateVerifierContract["verify((uint256,bytes32[]),uint256[],bytes32)"](merkleProof, DATA.risc0Agg.publicInputs, DATA.risc0Agg.vKeyHash)
    // receipt = await tx.wait()
    // console.log("risc0 aggregate verify::gasUsed", Number(receipt.gasUsed))

    // sp1 aggregate
    merkleProof = {"position": DATA.sp1Agg.merkleProofPosition, "elms": DATA.sp1Agg.merkleProof}
    tx = await aggregateVerifierContract["verify((uint256,bytes32[]),bytes,bytes32)"](merkleProof, DATA.sp1Agg.publicInputs, DATA.sp1Agg.vKeyHash)
    // receipt = await tx.wait()
    // console.log("sp1 aggregate verify::gasUsed", Number(receipt.gasUsed))

  });
});
