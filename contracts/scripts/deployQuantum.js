const hre = require("hardhat");

async function deployQuantum(verifierAddress, aggVerifierId) {
  const Quantum = await ethers.getContractFactory('lib/Quantum.sol:Quantum');
  const quantum = await Quantum.deploy(verifierAddress, aggVerifierId);
  await quantum.waitForDeployment();
  console.log("Quantum deployed to:", await quantum.getAddress());
  return await quantum.getAddress()
}

async function main() {
  const verifierAddress = "0xe33A179827d5BFDf0c58C956206197ac1098E8eD"
  const aggVerifierId = "0xa3c2d35e3c6295ea0dc45fbc441404bc761f4b2573bec2789ed2c7e428c1cabd"
  await deployQuantum(verifierAddress, aggVerifierId)

  // const quantum = await hre.ethers.getContractAt('lib/Quantum.sol:Quantum', "0x11DFD65dDc25A73A4d3a2EcbB968F749c1190490");
  // console.log("treeRoot:", await quantum.treeRoot());
}

if (require.main == module) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}


module.exports = { deployQuantum }