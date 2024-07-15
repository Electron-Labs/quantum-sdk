const fs = require('fs')
const { exec } = require('child_process');

const MAX_PUB_INPUTS = 20
const intToHexString = (n) => {
  return "0x" + n.toString(16)
}

const A = () => {
  return `// SPDX-License-Identifier: MIT
  pragma solidity ^0.8.24;

`
}

const B = (nPub) => {
  return `library ProtocolVerifier_${nPub} {
    uint256 constant SIGNATURE = 0x70e8daf7;

`
}

const C = (nPub) => {
  let code = `function verifyPubInputs(
    uint256[${nPub}] calldata pubInputs,
    bytes32 vkHash,
    address quantum_verifier
) internal {
    assembly {
        let p := mload(0x40)
        let zero := mload(0x60)\n
        `

  code += `// store public inputs\n`
  for (let i = 0; i < nPub; i++) {
    code += `mstore(add(p, ${intToHexString((i + 2) * 32)}), calldataload(${intToHexString(4 + i * 32)}))\n`
  }
  code += `// padd public inputs\n`
  for (let i = nPub; i < MAX_PUB_INPUTS; i++) {
    code += `mstore(add(p, ${intToHexString((i + 2) * 32)}), zero)\n`
  }
  code += `// public inputs hash
  mstore(add(p, 0x40), keccak256(add(p, 0x40), ${intToHexString(MAX_PUB_INPUTS * 32)}))\n\n`

  code += `// verify on quantum
  mstore(add(p, 0x20), vkHash)
  mstore(p, SIGNATURE)
  let ok := staticcall(
      gas(),
      quantum_verifier,
      add(p, 0x1c),
      0x24,
      p,
      0x20
  )
  if iszero(eq(mload(p), mload(add(p, 0x40)))) {
      revert(0, 0)
  }
}
}
}

`
  return code
}

async function main() {
  const nPubInputsRange = 15
  let code = A()
  for (let nPub = 1; nPub <= nPubInputsRange; nPub++) {
    code += B(nPub) + C(nPub)
  }

  fs.writeFile('./lib/ProtocolVerifier.sol', code, (err) => {
    if (err) throw err;
  })

  exec('sh prettier.sh',
    (error, stdout, stderr) => {
      console.log(stdout);
      console.log(stderr);
      if (error !== null) {
        console.log(`exec error: ${error}`);
      }
    });
}


if (require.main == module) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
