const hre = require("hardhat");

async function main() {
  const quantum = await hre.ethers.getContractAt('lib/Quantum.sol:Quantum', "0x33588B808Aafe5a3e1Bd1B5c999982cE7eAE09b6");
  console.log("setting verifier...")
  await quantum.setVerifier("0xA4a0FC353f6013eFA2900f8EcF907d8222493F33")
  console.log("setting verifier done!")
}

if (require.main == module) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
