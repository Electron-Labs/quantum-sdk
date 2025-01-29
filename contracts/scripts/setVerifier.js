const hre = require("hardhat");

async function main() {
  // const quantum = await hre.ethers.getContractAt('lib/Quantum.sol:Quantum', "0xaE5A309eba12Ae96a45ac580D4906Bbfac4E596f");

  // console.log("setting verifier...")
  // await quantum.setVerifier("0x99762F84D2BC82C11461997772149eCa2121F66d")
  // console.log("setting verifier done!")

  // console.log("setting aggVKey...")
  // await quantum.setAggVKey("0xec56b91c8c6ece365c3b2f74e388b79c926ab3a718f52a85316688fcdefcfb32")
  // console.log("setting aggVKey done!")
  // console.log(await quantum.aggVKey())
}

if (require.main == module) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
