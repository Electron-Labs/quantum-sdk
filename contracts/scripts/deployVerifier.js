const hre = require("hardhat");

async function deployVerifier() {
  const Verifier = await hre.ethers.getContractFactory("contracts/Verifier.sol:Verifier");
  const verifier = await hre.upgrades.deployProxy(Verifier);
  await verifier.waitForDeployment();
  console.log("Verifier deployed to:", await verifier.getAddress());
  return await verifier.getAddress()
}

async function main() {
  await deployVerifier()
}

if (require.main == module) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}


module.exports = { deployVerifier }