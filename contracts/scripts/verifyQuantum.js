const hardhat = require("hardhat")

async function main() {
  await hardhat.run("verify:verify", {
    address: "0x33588B808Aafe5a3e1Bd1B5c999982cE7eAE09b6",
    constructorArguments: ["0x747eA4AEC7Cea38872b47C1eADf67497E52a76e2", "0xbd7c1aa6ff0b352c711ef0b55c5b02981b91e340ac257ad4cc27e9bc072a447d"]
  })
}

if (require.main == module) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}