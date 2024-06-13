const hre = require("hardhat");

async function deployQuantum(initState) {
  const Quantum = await hre.ethers.getContractFactory("Quantum");
  const quantum = await hre.upgrades.deployProxy(Quantum, [initState]);
  await quantum.waitForDeployment();
  console.log("Quantum deployed to:", await quantum.getAddress());
  return await quantum.getAddress()
}

async function main() {
  // 0x851b17914fe4e0e307ad561560cad44c6d000a6d9e405c2ed3ba74693c162a76 // depth=10
  const initState = "0x1a5b34c687303c4a6b0afe27d93746a390e503e379cecb1f8ee82dd5240dccd7"
  await deployQuantum(initState)
}

if (require.main == module) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}


module.exports = { deployQuantum }