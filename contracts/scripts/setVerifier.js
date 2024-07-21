const hre = require("hardhat");

async function main() {
  const quantum = await hre.ethers.getContractAt('lib/Quantum.sol:Quantum', "0xBA19Cea5Bb79b0eE6674b704dd9a4a60169d888D");
  console.log("setting verifier...")
  await quantum.setVerifier("0xAc30E58986Ca88556867955923536B26Af31AFC7")
  console.log("setting verifier done!")
}

if (require.main == module) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
