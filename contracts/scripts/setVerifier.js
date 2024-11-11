const hre = require("hardhat");

async function main() {
  const quantum = await hre.ethers.getContractAt('lib/Quantum.sol:Quantum', "0x6afbB1c4296D2b4d333E24f2462b15f2D97449Cb");

  // console.log("setting verifier...")
  // await quantum.setVerifier("0x1Bd18f0ce16B122d83394a9553Bff4323b9ba669")
  // console.log("setting verifier done!")

  console.log("setting aggVerifierId...")
  await quantum.setAggVerifierId("0xb12eb8d931fe6fcd44355d7014ed14d6ac5fdffa75497c45c3f7e3544f3476db")
  console.log("setting aggVerifierId done!")
}

if (require.main == module) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
