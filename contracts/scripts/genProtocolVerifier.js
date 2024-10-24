const fs = require('fs')
const { exec } = require('child_process');

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
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE_SUPER_ROOT_VERIFIED = 0x55a22a85;

`
}

const C = (nPub) => {
  let code = `function verifyPubInputs(
    uint256[${nPub}] calldata pubInputs,
    uint256 merkleProofPosition,
    bytes32[] calldata merkleProof,
    bytes32 combinedVKeyHash,
    address quantum_verifier
) internal view {
    assembly {
        let p := mload(0x40)\n\n`

  code += `// ** compute leaf = keccak(combinedVKeyHash || keccak(pubInputs)) **
  // store pub inputs
  mstore(p, calldataload(0x4))\n`
  for (let i = 1; i < nPub; i++) {
    code += `mstore(add(p, ${intToHexString((i) * 32)}), calldataload(${intToHexString(4 + i * 32)}))\n`
  }
  code += `\n// keccak(pubInputs))
  mstore(add(p, 0x20), keccak256(p, ${intToHexString(nPub * 32)}))\n\n`

  code += `// combinedVKeyHash
  mstore(p, combinedVKeyHash)

  // storing leaf at p+0x40; all earlier data at any memory can be discarded
  mstore(add(p, 0x40), keccak256(p, 0x40))\n\n`

  code += `mstore(p, calldataload(${intToHexString(4 + (nPub * 32))})) // load merkle-proof-position at \`p\`\n\n`

  code += `// ** computing root (at \`p+0x40\`) using the proof elms and their position **\n`
  code += `let proofElmsSlotSize := mul(calldataload(${intToHexString(4 + ((nPub + 2) * 32))}), 0x20)
  for {
    let x := 0
} lt(x, proofElmsSlotSize) {
    x := add(x, 0x20)
} {
  switch and(mload(p), ONE)
      case 1 {
          mstore(add(p, 0x60), calldataload(add(${intToHexString(4 + ((nPub + 3) * 32))}, x)))
          mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
      }
      default {
          mstore(add(p, 0x20), calldataload(add(${intToHexString(4 + ((nPub + 3) * 32))}, x)))
          mstore(add(p, 0x40), keccak256(add(p, 0x20), 0x40))
      }
      mstore(p, shr(1, mload(p))) // update next position
  }\n\n`

  code += `mstore(add(p, 0x20), SIGNATURE_SUPER_ROOT_VERIFIED)
  let ok := staticcall(
      gas(),
      quantum_verifier,
      add(p, 0x3c),
      0x24,
      p,
      0x20
  )
  if iszero(eq(mload(p), ONE)) {
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
