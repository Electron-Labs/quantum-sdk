const hre = require("hardhat");

async function deployQuantum(verifierAddress, initRoot) {
  const Quantum = await ethers.getContractFactory('lib/Quantum.sol:Quantum');
  const quantum = await Quantum.deploy(verifierAddress, initRoot);
  console.log("Quantum deployed to:", await quantum.getAddress());
  return await quantum.getAddress()
}

async function main() {
  const verifierAddress = "0x90b2d5A113da90EC4637B9a095e4d037B6D699Be"
  const initRoot = "0x851b17914fe4e0e307ad561560cad44c6d000a6d9e405c2ed3ba74693c162a76"
  await deployQuantum(verifierAddress, initRoot)
}

if (require.main == module) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}


module.exports = { deployQuantum }