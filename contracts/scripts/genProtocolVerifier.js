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
    uint256 constant SIGNATURE_PUB_INPUTS_HASH = 0x4015817b;
    uint256 constant SIGNATURE_TREE_ROOT = 0x14dc6c14;

    struct ProtocolInclusionProof {
        uint256 merkleProofPosition;
        bytes32[10] merkleProof;
        bytes32 leafNextValue;
        bytes8 leafNextIdx;
    }

`
}

const C = (nPub) => {
  let code = `function verifyLatestPubInputs(
    uint256[${nPub}] calldata pubInputs,
    bytes32 vkHash,
    address quantum_verifier
) internal view {
    assembly {
        let p := mload(0x40)
        let zero := mload(0x60)\n
        `

  code += `// store public inputs\n`
  for (let i = 0; i < nPub; i++) {
    code += `mstore(add(p, ${intToHexString((i + 2) * 32)}), calldataload(${intToHexString(4 + i * 32)}))\n`
  }
  code += `// public inputs hash
  mstore(add(p, 0x40), keccak256(add(p, 0x40), ${intToHexString(nPub * 32)}))\n\n`

  code += `// verify on quantum
  mstore(add(p, 0x20), vkHash)
  mstore(p, SIGNATURE_PUB_INPUTS_HASH)
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

`
  return code
}

const D = (nPub) => {
  let code = `function verifyOldPubInputs(
    ProtocolInclusionProof calldata protocolInclusionProof,
    uint256[${nPub}] calldata pubInputs,
    bytes32 vKeyHash,
    address quantum_verifier
) internal view {
    assembly {
        let p := mload(0x40)
        let zero := mload(0x60)\n\n`

  code += `// ** computer leaf value = keccak(vKeyHash || keccak(extend(pubInputs))) **
  // store pub inputs
  mstore(p, calldataload(0x1a4))\n`
  for (let i = 1; i < nPub; i++) {
    code += `mstore(add(p, ${intToHexString(i * 32)}), calldataload(${intToHexString(420 + i * 32)}))\n`
  }
  code += `\n// keccak(extend(pubInputs)))
  mstore(add(p, 0x20), keccak256(p, ${intToHexString(nPub * 32)}))

  // vKeyHash
  mstore(p, vKeyHash)

  // construct leaf
  mstore(add(p, 0x40), keccak256(p, 0x40)) // leaf value
  mstore(add(p, 0x60), calldataload(0x164)) // leaf next value
  mstore(add(p, 0x80), calldataload(0x184)) // leaf next idx

  // compute leafHash
  mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x48)) //  storing leafHash at p+0x40; all earlier data at any memory can be discarded

  mstore(p, calldataload(0x4)) // load merkle-proof-position at \`p\`

  // computing root (at \`p+0x40\`) using 10 proof elms and their position
  switch and(mload(p), ONE)
  case 1 {
      mstore(add(p, 0x60), calldataload(0x24))
      mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
  }
  default {
      mstore(add(p, 0x20), calldataload(0x24))
      mstore(add(p, 0x40), keccak256(add(p, 0x20), 0x40))
  }
  mstore(p, shr(1, mload(p))) // update next position

  switch and(mload(p), ONE)
  case 1 {
      mstore(add(p, 0x60), calldataload(0x44))
      mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
  }
  default {
      mstore(add(p, 0x20), calldataload(0x44))
      mstore(add(p, 0x40), keccak256(add(p, 0x20), 0x40))
  }
  mstore(p, shr(1, mload(p))) // update next position

  switch and(mload(p), ONE)
  case 1 {
      mstore(add(p, 0x60), calldataload(0x64))
      mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
  }
  default {
      mstore(add(p, 0x20), calldataload(0x64))
      mstore(add(p, 0x40), keccak256(add(p, 0x20), 0x40))
  }
  mstore(p, shr(1, mload(p))) // update next position

  switch and(mload(p), ONE)
  case 1 {
      mstore(add(p, 0x60), calldataload(0x84))
      mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
  }
  default {
      mstore(add(p, 0x20), calldataload(0x84))
      mstore(add(p, 0x40), keccak256(add(p, 0x20), 0x40))
  }
  mstore(p, shr(1, mload(p))) // update next position

  switch and(mload(p), ONE)
  case 1 {
      mstore(add(p, 0x60), calldataload(0xa4))
      mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
  }
  default {
      mstore(add(p, 0x20), calldataload(0xa4))
      mstore(add(p, 0x40), keccak256(add(p, 0x20), 0x40))
  }
  mstore(p, shr(1, mload(p))) // update next position

  switch and(mload(p), ONE)
  case 1 {
      mstore(add(p, 0x60), calldataload(0xc4))
      mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
  }
  default {
      mstore(add(p, 0x20), calldataload(0xc4))
      mstore(add(p, 0x40), keccak256(add(p, 0x20), 0x40))
  }
  mstore(p, shr(1, mload(p))) // update next position

  switch and(mload(p), ONE)
  case 1 {
      mstore(add(p, 0x60), calldataload(0xe4))
      mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
  }
  default {
      mstore(add(p, 0x20), calldataload(0xe4))
      mstore(add(p, 0x40), keccak256(add(p, 0x20), 0x40))
  }
  mstore(p, shr(1, mload(p))) // update next position

  switch and(mload(p), ONE)
  case 1 {
      mstore(add(p, 0x60), calldataload(0x104))
      mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
  }
  default {
      mstore(add(p, 0x20), calldataload(0x104))
      mstore(add(p, 0x40), keccak256(add(p, 0x20), 0x40))
  }
  mstore(p, shr(1, mload(p))) // update next position

  switch and(mload(p), ONE)
  case 1 {
      mstore(add(p, 0x60), calldataload(0x124))
      mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
  }
  default {
      mstore(add(p, 0x20), calldataload(0x124))
      mstore(add(p, 0x40), keccak256(add(p, 0x20), 0x40))
  }
  mstore(p, shr(1, mload(p))) // update next position

  switch and(mload(p), ONE)
  case 1 {
      mstore(add(p, 0x60), calldataload(0x144))
      mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
  }
  default {
      mstore(add(p, 0x20), calldataload(0x144))
      mstore(add(p, 0x40), keccak256(add(p, 0x20), 0x40))
  }

  mstore(p, SIGNATURE_TREE_ROOT)
  let ok := staticcall(
      gas(),
      quantum_verifier,
      add(p, 0x1c),
      0x4,
      add(p, 0x20),
      0x20
  )
  if iszero(eq(mload(add(p, 0x20)), mload(add(p, 0x40)))) {
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
    code += B(nPub) + C(nPub) + D(nPub)
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
