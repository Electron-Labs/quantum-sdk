const hre = require("hardhat");

async function deployProtocolVerifier(quantumAddress, vKeyHash) {
  const ProtocolVerifier = await hre.ethers.getContractFactory("contracts/ProtocolVerifier.sol:ProtocolVerifier");
  const protocolVerifier = await hre.upgrades.deployProxy(ProtocolVerifier, [quantumAddress, vKeyHash]);
  await protocolVerifier.waitForDeployment();
  console.log("ProtocolVerifier deployed to:", await protocolVerifier.getAddress());
  return await protocolVerifier.getAddress()
}

async function main() {
  const quantumAddress = "0x"
  const protocolVKeyHash = "0x"
  const reductionVKeyHash = "0x"
  await deployProtocolVerifier(quantumAddress, protocolVKeyHash, reductionVKeyHash)
}

if (require.main == module) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}


module.exports = { deployProtocolVerifier }