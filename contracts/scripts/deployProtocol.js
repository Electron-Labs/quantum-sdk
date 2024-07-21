const hre = require("hardhat");

async function deployProtocol(vKeyHash) {
  const Protocol = await hre.ethers.getContractFactory('Protocol');
  const protocol = await Protocol.deploy(vKeyHash);
  console.log("protocol deployed at:", await protocol.getAddress())
  return await protocol.getAddress()
}

async function main() {
  const vKeyHash = "0x6f1ed928259d5825233e8b7be624b3968154993c7f7575d1e0451f61883400e2"
  await deployProtocol(vKeyHash)
}

if (require.main == module) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}


module.exports = { deployProtocol }