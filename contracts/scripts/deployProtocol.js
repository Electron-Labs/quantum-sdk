const hre = require("hardhat");

async function deployProtocol(circuitHash) {
  const Protocol = await hre.ethers.getContractFactory('Protocol');
  const protocol = await Protocol.deploy(circuitHash);
  console.log("protocol deployed at:", await protocol.getAddress())
  return await protocol.getAddress()
}

async function main() {
  const circuitHash = "0x6f1ed928259d5825233e8b7be624b3968154993c7f7575d1e0451f61883400e2"
  await deployProtocol(circuitHash)
}

if (require.main == module) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}


module.exports = { deployProtocol }