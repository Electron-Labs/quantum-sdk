const hre = require("hardhat");

async function deployProtocol(vKeyHash) {
  const Protocol = await hre.ethers.getContractFactory('Protocol');
  const protocol = await Protocol.deploy(vKeyHash);
  console.log("protocol deployed at:", await protocol.getAddress())
  return await protocol.getAddress()
}

async function main() {
  const vKeyHash = "0x87a5b3814d26dbf2d74832e65c4230a3ce33b39438c036ae09c20e97e20a5671"
  await deployProtocol(vKeyHash)
}

if (require.main == module) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}


module.exports = { deployProtocol }