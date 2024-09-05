const fs = require('fs')
const { exec } = require('child_process');

const intToHexString = (n) => {
  return "0x" + n.toString(16)
}

const A = () => {
  return `// SPDX-License-Identifier: MIT
  pragma solidity ^0.8.24;
  import {IQuantum} from "./interfaces/IQuantum.sol";

`
}

const B = (nProtocol, IMT_VK_HASH) => {
  return `contract Quantum_${nProtocol} {
    address public verifier;
    address public owner;

    mapping(bytes32 => bytes32) public pubInputsHashes;
    bytes32 public treeRoot;

    uint256 constant SIGNATURE = 0xb2ff0a36;
    uint256 constant IMT_VK_HASH = ${IMT_VK_HASH};

    struct Protocol {
        bytes32 vkHash;
        bytes32 pubInputsHash;
    }
    struct Batch {
        Protocol[${nProtocol}] protocols;
    }
    struct Proof {
        uint256[8] proof;
        uint256[2] commitments;
        uint256[2] commitmentPok;
    }
    struct TreeUpdate {
        bytes32 newRoot;
    }

    constructor(address verifier_, bytes32 initRoot) {
        owner = msg.sender;
        verifier = verifier_;
        treeRoot = initRoot;
    }

    function registerProtocol(bytes32 vkHash) external {
        pubInputsHashes[
            vkHash
        ] = 0x0100000000000000000000000000000000000000000000000000000000000000;
    }

`
}

const C = (nProtocol) => {
  let code = `function verifySuperproof(
    Proof calldata proof,
    Batch calldata batch,
    TreeUpdate calldata treeUpdate
) external {
    assembly {
        let p := mload(0x40)

        // store batch
        `

  code += `mstore(p, calldataload(0x184))
  mstore(add(p, 0x20), calldataload(0x1a4))
  `

  for (let i = 1; i < nProtocol; i++) {
    code += `mstore(add(p, ${intToHexString(2 * i * 32)}), calldataload(${intToHexString(388 + 2 * i * 32)}))
    mstore(add(p, ${intToHexString((2 * i + 1) * 32)}), calldataload(${intToHexString(388 + (2 * i + 1) * 32)}))
    `
  }

  code += `// store old root
  mstore(add(p, ${intToHexString(2 * nProtocol * 32)}), sload(treeRoot.slot))
  `

  code += `// store new root
  mstore(add(p, ${intToHexString((2 * nProtocol + 1) * 32)}), calldataload(${intToHexString(388 + 2 * nProtocol * 32)}))`

  code += `\n// store IMT vk hash
            mstore(add(p, ${intToHexString((2 * nProtocol + 2) * 32)}), IMT_VK_HASH)`

  code += `\n// pub inputs serialized
  mstore(p, keccak256(p, ${intToHexString(nProtocol * 32 * 2 + 32 + 32 + 32)}))\n\n`


  code += `// store public inputs just after the proof stored in the next step
  mstore(add(p, 0x1a0), shr(128, mload(p))) // pub1
  mstore(
      add(p, 0x1c0),
      and(mload(p), 0xffffffffffffffffffffffffffffffff)
  ) // pub2

  // copy proof from calldata
  mstore(add(p, 0x20), calldataload(0x4))
  mstore(add(p, 0x40), calldataload(0x24))
  mstore(add(p, 0x60), calldataload(0x44))
  mstore(add(p, 0x80), calldataload(0x64))
  mstore(add(p, 0xa0), calldataload(0x84))
  mstore(add(p, 0xc0), calldataload(0xa4))
  mstore(add(p, 0xe0), calldataload(0xc4))
  mstore(add(p, 0x100), calldataload(0xe4))
  mstore(add(p, 0x120), calldataload(0x104))
  mstore(add(p, 0x140), calldataload(0x124))
  mstore(add(p, 0x160), calldataload(0x144))
  mstore(add(p, 0x180), calldataload(0x164))

  // store verifyProof's function signature
  mstore(p, SIGNATURE)

  // verify proof
  let ok := staticcall(
      gas(),
      sload(verifier.slot),
      add(p, 0x1c),
      0x1c4,
      0,
      0
  )
  if iszero(ok) {
      revert(0, 0)
  }

  // update state - treeRoot
  sstore(treeRoot.slot, calldataload(${intToHexString(388 + 2 * nProtocol * 32)}))
}\n\n`

  for (let i = 0; i < nProtocol; i++) {
    code += `pubInputsHashes[batch.protocols[${i}].vkHash] = batch
  .protocols[${i}]
  .pubInputsHash;
  `
  }

  code += `}\n\n`

  return code
}

const D = () => {
  let code = `function setVerifier(address verifierAddress) external {
    if (msg.sender != owner) {
        revert("!owner");
    }
    verifier = verifierAddress;
}
}
`

  return code
}

async function main() {
  const nProtocols = 20
  const IMT_VK_HASH = "0xa8be9d622bc3bc1bb49c7682a4a74c85a3cc937e52ff7aac5fd1369bff86044f"
  let code = A() + B(nProtocols, IMT_VK_HASH) + C(nProtocols) + D()

  fs.writeFile(`./lib/Quantum_${nProtocols}.sol`, code, (err) => {
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