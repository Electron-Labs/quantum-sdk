// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {IQuantum} from "./interfaces/IQuantum.sol";

contract Quantum_1 {
    address public verifier;
    address public owner;
    mapping(bytes32 => bytes32) public pubInputsHashes;

    uint256 constant SIGNATURE = 0xb2ff0a36;

    struct Protocol {
        bytes32 vkHash;
        bytes32 pubInputsHash;
    }
    struct Batch {
        Protocol[1] protocols;
    }
    struct Proof {
        uint256[8] proof;
        uint256[2] commitments;
        uint256[2] commitmentPok;
    }

    constructor(address verifier_) {
        owner = msg.sender;
        verifier = verifier_;
    }

    function registerProtocol(bytes32 vkHash) external {
        pubInputsHashes[
            vkHash
        ] = 0x0100000000000000000000000000000000000000000000000000000000000000;
    }

    function verifySuperproof(Proof calldata proof, Batch calldata batch) external {
        assembly {
            let p := mload(0x40)

            mstore(p, calldataload(0x184))
            mstore(add(p, 0x20), calldataload(0x1a4))
            // mstore(add(p, 0x40), calldataload(0x1c4))
            // mstore(add(p, 0x60), calldataload(0x1e4))
            // mstore(add(p, 0x80), calldataload(0x204))
            // mstore(add(p, 0xa0), calldataload(0x224))
            // mstore(add(p, 0xc0), calldataload(0x244))
            // mstore(add(p, 0xe0), calldataload(0x264))
            // mstore(add(p, 0x100), calldataload(0x284))
            // mstore(add(p, 0x120), calldataload(0x2a4))
            // mstore(add(p, 0x140), calldataload(0x2c4))
            // mstore(add(p, 0x160), calldataload(0x2e4))
            // mstore(add(p, 0x180), calldataload(0x304))
            // mstore(add(p, 0x1a0), calldataload(0x324))
            // mstore(add(p, 0x1c0), calldataload(0x344))
            // mstore(add(p, 0x1e0), calldataload(0x364))
            // mstore(add(p, 0x200), calldataload(0x384))
            // mstore(add(p, 0x220), calldataload(0x3a4))
            // mstore(add(p, 0x240), calldataload(0x3c4))
            // mstore(add(p, 0x260), calldataload(0x3e4))

            mstore(p, keccak256(p, 0x40))
            // mstore(p, keccak256(p, 0x280))

            // store public inputs just after the proof stored in the next step
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
        }

        pubInputsHashes[batch.protocols[0].vkHash] = batch
            .protocols[0]
            .pubInputsHash;
        // pubInputsHashes[batch.protocols[1].vkHash] = batch
        //     .protocols[1]
        //     .pubInputsHash;
        // pubInputsHashes[batch.protocols[2].vkHash] = batch
        //     .protocols[2]
        //     .pubInputsHash;
        // pubInputsHashes[batch.protocols[3].vkHash] = batch
        //     .protocols[3]
        //     .pubInputsHash;
        // pubInputsHashes[batch.protocols[4].vkHash] = batch
        //     .protocols[4]
        //     .pubInputsHash;
        // pubInputsHashes[batch.protocols[5].vkHash] = batch
        //     .protocols[5]
        //     .pubInputsHash;
        // pubInputsHashes[batch.protocols[6].vkHash] = batch
        //     .protocols[6]
        //     .pubInputsHash;
        // pubInputsHashes[batch.protocols[7].vkHash] = batch
        //     .protocols[7]
        //     .pubInputsHash;
        // pubInputsHashes[batch.protocols[8].vkHash] = batch
        //     .protocols[8]
        //     .pubInputsHash;
        // pubInputsHashes[batch.protocols[9].vkHash] = batch
        //     .protocols[9]
        //     .pubInputsHash;
    }
}

contract Quantum {
    address public verifier;
    address public owner;
    mapping(bytes32 => bytes32) public pubInputsHashes;

    uint256 constant SIGNATURE = 0xb2ff0a36;

    struct Protocol {
        bytes32 vkHash;
        bytes32 pubInputsHash;
    }
    struct Batch {
        Protocol[10] protocols;
    }
    struct Proof {
        uint256[8] proof;
        uint256[2] commitments;
        uint256[2] commitmentPok;
    }

    constructor(address verifier_) {
        owner = msg.sender;
        verifier = verifier_;
    }

    function registerProtocol(bytes32 vkHash) external {
        pubInputsHashes[
            vkHash
        ] = 0x0100000000000000000000000000000000000000000000000000000000000000;
    }

    function verifySuperproof(Proof calldata proof, Batch calldata batch) external {
        assembly {
            let p := mload(0x40)

            mstore(p, calldataload(0x184))
            mstore(add(p, 0x20), calldataload(0x1a4))
            mstore(add(p, 0x40), calldataload(0x1c4))
            mstore(add(p, 0x60), calldataload(0x1e4))
            mstore(add(p, 0x80), calldataload(0x204))
            mstore(add(p, 0xa0), calldataload(0x224))
            mstore(add(p, 0xc0), calldataload(0x244))
            mstore(add(p, 0xe0), calldataload(0x264))
            mstore(add(p, 0x100), calldataload(0x284))
            mstore(add(p, 0x120), calldataload(0x2a4))
            mstore(add(p, 0x140), calldataload(0x2c4))
            mstore(add(p, 0x160), calldataload(0x2e4))
            mstore(add(p, 0x180), calldataload(0x304))
            mstore(add(p, 0x1a0), calldataload(0x324))
            mstore(add(p, 0x1c0), calldataload(0x344))
            mstore(add(p, 0x1e0), calldataload(0x364))
            mstore(add(p, 0x200), calldataload(0x384))
            mstore(add(p, 0x220), calldataload(0x3a4))
            mstore(add(p, 0x240), calldataload(0x3c4))
            mstore(add(p, 0x260), calldataload(0x3e4))

            mstore(p, keccak256(p, 0x280))

            // store public inputs just after the proof stored in the next step
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
        }

        pubInputsHashes[batch.protocols[0].vkHash] = batch
            .protocols[0]
            .pubInputsHash;
        pubInputsHashes[batch.protocols[1].vkHash] = batch
            .protocols[1]
            .pubInputsHash;
        pubInputsHashes[batch.protocols[2].vkHash] = batch
            .protocols[2]
            .pubInputsHash;
        pubInputsHashes[batch.protocols[3].vkHash] = batch
            .protocols[3]
            .pubInputsHash;
        pubInputsHashes[batch.protocols[4].vkHash] = batch
            .protocols[4]
            .pubInputsHash;
        pubInputsHashes[batch.protocols[5].vkHash] = batch
            .protocols[5]
            .pubInputsHash;
        pubInputsHashes[batch.protocols[6].vkHash] = batch
            .protocols[6]
            .pubInputsHash;
        pubInputsHashes[batch.protocols[7].vkHash] = batch
            .protocols[7]
            .pubInputsHash;
        pubInputsHashes[batch.protocols[8].vkHash] = batch
            .protocols[8]
            .pubInputsHash;
        pubInputsHashes[batch.protocols[9].vkHash] = batch
            .protocols[9]
            .pubInputsHash;
    }
}
