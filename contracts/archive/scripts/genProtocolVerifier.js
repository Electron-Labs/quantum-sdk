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
    uint256 constant SIGNATURE = 0xc19d93fb;

`
}

const C = (nPub) => {
  let code = `struct ProtocolInclusionProof {
    bytes32 protocolVKeyHash;
    bytes32 reductionVKeyHash;
    uint256 merkleProofPosition;
    bytes32[10] merkleProof;
    bytes32 leafNextValue;
    bytes8 leafNextIdx;
`

  if (nPub > 0) {
    code += `    bytes32[${nPub}] pubInputs;
`
  }

  code += `\n}\n\n`

  return code
}

const D = (nPub) => {
  let code = `function verifyPubInputs(
  ProtocolInclusionProof calldata protocolInclusionProof,
  bytes32 vKeyHash,
  address quantum_verifier
) internal {
  assembly {
      let p := mload(0x40)

      // reduced pub inputs = compute keccak(protocolVKeyHash || pubInputs...)
      mstore(p, calldataload(0x4))
`

  for (let i = 0; i < nPub; i++) {
    code += `            mstore(add(p, ${intToHexString((i + 1) * 32)}), calldataload(${intToHexString(4 + (i + 15) * 32)}))\n`
  }
  code += `            mstore(add(p, 0x60), keccak256(p, ${intToHexString((1 + nPub) * 32)}))

`

  return code
}

const E = () => {
  return `            // pad reduced pub inputs
  mstore(
      add(p, 0x80),
      and(
          mload(add(p, 0x60)),
          0xffffffffffffffffffffffffffffffff00000000000000000000000000000000
      )
  )
  mstore(add(p, 0xa0), shl(128, mload(add(p, 0x60))))

  // compute leafValue = keccak(reductionVKeyHash || padded(keccak(protocolVKeyHash || pubInputs...)))
  mstore(add(p, 0x60), calldataload(0x24))
  mstore(add(p, 0x40), keccak256(add(p, 0x60), 0x60))

  // check keccak(protocolVKeyHash || reductionVKeyHash) ==  vKeyHash (state var)
  mstore(add(p, 0x20), calldataload(0x24))
  mstore(p, keccak256(p, 0x40))
  mstore(add(p, 0x20), vKeyHash)
  if iszero(eq(mload(p), mload(add(p, 0x20)))) {
      revert(0, 0)
  }

  // compute leafHash
  mstore(add(p, 0x60), calldataload(0x1a4))
  mstore(add(p, 0x80), calldataload(0x1c4))
  mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x48)) //  storing leafHash at p+0x40; all earlier data at any memory can be discarded

  mstore(p, calldataload(0x44)) // load merkle-proof-position at \`p\`

  // computing root (at \`p+0x40\`) using 10 proof elms and their position
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
  mstore(p, shr(1, mload(p))) // update next position

  switch and(mload(p), ONE)
  case 1 {
      mstore(add(p, 0x60), calldataload(0x164))
      mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
  }
  default {
      mstore(add(p, 0x20), calldataload(0x164))
      mstore(add(p, 0x40), keccak256(add(p, 0x20), 0x40))
  }
  mstore(p, shr(1, mload(p))) // update next position

  switch and(mload(p), ONE)
  case 1 {
      mstore(add(p, 0x60), calldataload(0x184))
      mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
  }
  default {
      mstore(add(p, 0x20), calldataload(0x184))
      mstore(add(p, 0x40), keccak256(add(p, 0x20), 0x40))
  }

  mstore(p, SIGNATURE)
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
}

async function main() {
  const nPubInputsRange = 15
  let code = A()
  for (let nPub = 0; nPub <= nPubInputsRange; nPub++) {
    code += B(nPub) + C(nPub) + D(nPub) + E()
  }

  fs.writeFile('./src/ProtocolVerifier.sol', code, (err) => {
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
