const hre = require("hardhat");

async function main() {
  const quantum = await hre.ethers.getContractAt('lib/Quantum.sol:Quantum', "0x56ED0e586D5B929A603a56d1D0FeF5280C9Cc33e");

  // console.log("setting verifier...")
  // await quantum.setVerifier("0x62ebaF6B6Eaf21b64F374f353f60BC80C1a22720")
  // console.log("setting verifier done!")

  console.log("setting aggVerifierId...")
  await quantum.setAggVerifierid("0x5de53581e9e02c82db2752ad472bb9c5cd237f67ae7414e6adebf6098b406ebc")
  console.log("setting aggVerifierId done!")
}

if (require.main == module) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
