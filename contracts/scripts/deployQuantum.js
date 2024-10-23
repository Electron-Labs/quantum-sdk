const hre = require("hardhat");
const { upgrades } = require("hardhat")

async function deployQuantum(verifierAddress, aggVerifierId) {
  const Quantum = await hre.ethers.getContractFactory('lib/Quantum.sol:Quantum');
  const quantum = await upgrades.deployProxy(Quantum, [verifierAddress, aggVerifierId], { kind: 'uups' })
  console.log("Quantum deployed to:", await quantum.getAddress());
  return await quantum.getAddress()
}

async function main() {
  const verifierAddress = "0x2840C36927cbb8Af17d1d23830617707655fF6b1"
  const aggVerifierId = "0x595197c139011ce12abdc6612c2ee7f3f6ee3591bc109d7e7c3d3215f74bfb80"
  await deployQuantum(verifierAddress, aggVerifierId)
}

if (require.main == module) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}


module.exports = { deployQuantum }