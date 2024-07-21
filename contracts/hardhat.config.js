const dotenv = require('dotenv')
require("@nomicfoundation/hardhat-toolbox");
require('@openzeppelin/hardhat-upgrades');

dotenv.config()

const SEPOLIA_PRIVATE_KEY = process.env.SEPOLIA_PRIVATE_KEY
const SEPOLIA_RPC = process.env.SEPOLIA_RPC


/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {

  solidity: {
    compilers: [
      {
        version: "0.8.24",
        settings: {
          optimizer: {
            enabled: true,
            runs: 2000,
          },
        }
      },
      {
        version: "0.8.19",
        settings: {
          optimizer: {
            enabled: true,
            runs: 200,
          },
        }
      },
    ]
  },
  networks: {
    sepolia: {
      url: SEPOLIA_RPC,
      accounts: [SEPOLIA_PRIVATE_KEY],
    },
    localhost_sepolia: {
      url: `http://localhost:8545`,
    },
  },
  paths: {
    sources: "./lib",
  }
};