const hardhat = require("hardhat")

async function main() {
  await hardhat.run("verify:verify", {
    address: "0x99762F84D2BC82C11461997772149eCa2121F66d",
    constructorArguments: []
  })
}

if (require.main == module) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}