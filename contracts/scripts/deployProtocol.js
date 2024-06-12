const hre = require("hardhat");

async function deployProtocol(vKeyHash) {
  const Protocol = await hre.ethers.getContractFactory("Protocol_4");
  const protocol = await hre.upgrades.deployProxy(Protocol, [vKeyHash]);
  await protocol.waitForDeployment();
  console.log("Protocol deployed to:", await protocol.getAddress());
  return await protocol.getAddress()
}

async function main() {
  const vKeyHash = "0xfd77718d2fb7695650cfdaa93b8753a98ae988244df741f7b084528a6dbb85dd"
  await deployProtocol(vKeyHash)
}

if (require.main == module) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}


module.exports = { deployProtocol }