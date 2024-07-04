const hre = require("hardhat");

async function deployQuantum(verifierAddress) {
  const Quantum = await ethers.getContractFactory('lib/Quantum.sol:Quantum');
  const quantum = await Quantum.deploy(verifierAddress);
  console.log("Quantum deployed to:", await quantum.getAddress());
  return await quantum.getAddress()
}

async function main() {
  const verifierAddress = "0x0661a639856E97c58dd2768E215526bBaA12B4A8"
  await deployQuantum(verifierAddress)
}

if (require.main == module) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}


module.exports = { deployQuantum }