const hre = require("hardhat");

async function deployQuantum(verifierAddress, initRoot) {
  const Quantum = await ethers.getContractFactory('lib/Quantum.sol:Quantum');
  const quantum = await Quantum.deploy(verifierAddress, initRoot);
  console.log("Quantum deployed to:", await quantum.getAddress());
  return await quantum.getAddress()
}

async function main() {
  const verifierAddress = "0x747eA4AEC7Cea38872b47C1eADf67497E52a76e2"
  const initRoot = "0x8897fc2084ca305a7d637e9cdae101c6847fb76b1b2e67f04144f517a75da890"
  await deployQuantum(verifierAddress, initRoot)

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