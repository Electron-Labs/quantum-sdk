const hre = require("hardhat");

async function deployProtocol(vKeyHash) {
  const Protocol = await hre.ethers.getContractFactory("Protocol");
  const protocol = await hre.upgrades.deployProxy(Protocol, [vKeyHash]);
  await protocol.waitForDeployment();
  console.log("Protocol deployed to:", await protocol.getAddress());
  return await protocol.getAddress()
}

async function main() {
  const quantumAddress = "0x"
  const protocolVKeyHash = "0x"
  const reductionVKeyHash = "0x"
  await deployProtocol(quantumAddress, protocolVKeyHash, reductionVKeyHash)
}

if (require.main == module) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}


module.exports = { deployProtocol }