const hre = require("hardhat");
const { upgrades } = require("hardhat")

async function deployQuantum(verifierAddress, aggVKey) {
  const Quantum = await hre.ethers.getContractFactory('lib/Quantum.sol:Quantum');
  const quantum = await upgrades.deployProxy(Quantum, [verifierAddress, aggVKey], { kind: 'uups' })
  console.log("Quantum deployed to:", await quantum.getAddress());
  return await quantum.getAddress()
}

async function main() {
  const verifierAddress = "0x4b4eAd050aC324aDe3a02847d8036546336A9B1F"
  const aggVKey = "0xff5e3140dbd03b8bf7cf4fda97ba61bb4afb9477d2ab7b21a981778b1880600d"
  await deployQuantum(verifierAddress, aggVKey)
}

if (require.main == module) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}


module.exports = { deployQuantum }