const hre = require("hardhat");

async function deployAggregateVerifier(circuitHash) {
  const AggregateVerifier = await hre.ethers.getContractFactory('AggregateVerifier');
  const aggregateVerifier = await AggregateVerifier.deploy();
  console.log("AggregateVerifier deployed at:", await aggregateVerifier.getAddress())
  return await aggregateVerifier.getAddress()
}

async function main() {
  await deployAggregateVerifier()
}

if (require.main == module) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}


module.exports = { deployAggregateVerifier }