const hre = require("hardhat");

async function main() {
  const quantum = await hre.ethers.getContractAt('lib/Quantum.sol:Quantum', "0x11DFD65dDc25A73A4d3a2EcbB968F749c1190490");
  console.log("setting verifier...")
  await quantum.setVerifier("0x62ebaF6B6Eaf21b64F374f353f60BC80C1a22720")
  console.log("setting verifier done!")
}

if (require.main == module) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
