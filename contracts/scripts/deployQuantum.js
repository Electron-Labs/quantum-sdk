const hre = require("hardhat");

async function deployQuantum(verifierAddress, initRoot, aggVerifierId) {
  const Quantum = await ethers.getContractFactory('lib/Quantum.sol:Quantum');
  const quantum = await Quantum.deploy(verifierAddress, initRoot, aggVerifierId);
  await quantum.waitForDeployment();
  console.log("Quantum deployed to:", await quantum.getAddress());
  return await quantum.getAddress()
}

async function main() {
  const verifierAddress = "0x747eA4AEC7Cea38872b47C1eADf67497E52a76e2"
  const initRoot = "0xbd7c1aa6ff0b352c711ef0b55c5b02981b91e340ac257ad4cc27e9bc072a447d"
  const aggVerifierId = "0x"
  await deployQuantum(verifierAddress, initRoot, aggVerifierId)

  // const quantum = await hre.ethers.getContractAt('lib/Quantum.sol:Quantum', "0xd6aD4d6D83803f56032170a9d2ce71b030A1f4BC");
  // console.log("treeRoot:", await quantum.treeRoot());
}

if (require.main == module) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}


module.exports = { deployQuantum }