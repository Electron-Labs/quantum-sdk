const hre = require("hardhat");

async function deployQuantum(verifierAddress, initRoot, aggVerifierId) {
  const Quantum = await ethers.getContractFactory('lib/Quantum.sol:Quantum');
  const quantum = await Quantum.deploy(verifierAddress, initRoot, aggVerifierId);
  await quantum.waitForDeployment();
  console.log("Quantum deployed to:", await quantum.getAddress());
  return await quantum.getAddress()
}

async function main() {
  const verifierAddress = "0xc01707bD835f6108785DF081C943C7C108FC3D89"
  const initRoot = "0x851b17914fe4e0e307ad561560cad44c6d000a6d9e405c2ed3ba74693c162a76"
  const aggVerifierId = "0x1a786d63e2ca32d6ab700876d38491780c9c0bcaaa326bb06885f93fe05c2ccf"
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