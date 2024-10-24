const hre = require("hardhat");

async function main() {
  const quantum = await hre.ethers.getContractAt('lib/Quantum.sol:Quantum', "0x6afbB1c4296D2b4d333E24f2462b15f2D97449Cb");

  console.log("setting verifier...")
  await quantum.setVerifier("0x1Bd18f0ce16B122d83394a9553Bff4323b9ba669")
  console.log("setting verifier done!")

  // console.log("setting aggVerifierId...")
  // await quantum.setAggVerifierid("0x5de53581e9e02c82db2752ad472bb9c5cd237f67ae7414e6adebf6098b406ebc")
  // console.log("setting aggVerifierId done!")
}

if (require.main == module) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
