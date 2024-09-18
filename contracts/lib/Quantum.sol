// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {IQuantum} from "./interfaces/IQuantum.sol";

contract Quantum {
    uint256 constant SIGNATURE = 0xb2ff0a36;

    bytes32 public treeRoot;
    bytes32 private aggVerifierId;
    address public owner;
    address public verifier;

    struct Protocol {
        bytes32 combinedVkeyHash;
        bytes32 pisHash;
    }
    struct Proof {
        uint256[8] proof;
        uint256[2] commitments;
        uint256[2] commitmentPok;
    }
    struct TreeUpdate {
        bytes32 newRoot;
    }

    constructor(address verifier_, bytes32 initRoot, bytes32 aggVerifierId_) {
        owner = msg.sender;
        verifier = verifier_;
        treeRoot = initRoot;
        aggVerifierId = aggVerifierId_;
    }

    function registerProtocol(bytes32 combinedVKeyHash) external {
        assembly {
            sstore(
                combinedVKeyHash,
                0x0100000000000000000000000000000000000000000000000000000000000000
            )
        }
    }

    function verifySuperproof(
        Proof calldata proof,
        Protocol[] calldata protocols,
        TreeUpdate calldata treeUpdate
    ) external {
        assembly {
            let p := mload(0x40)

            // store batch
            let batchSlotSize := mul(calldataload(0x1c4), 0x40)
            for {
                let x := 0
            } lt(x, batchSlotSize) {
                x := add(x, 0x40)
            } {
                mstore(add(p, x), calldataload(add(0x1e4, x)))
                mstore(
                    add(p, add(x, 0x20)),
                    calldataload(add(0x1e4, add(x, 0x20)))
                )
                sstore(
                    calldataload(add(0x1e4, x)),
                    calldataload(add(0x1e4, add(x, 0x20)))
                )
            }

            // store old root
            let oldRootPos := add(p, batchSlotSize)
            mstore(oldRootPos, sload(treeRoot.slot))

            // store new root
            let newRoot := calldataload(0x1a4)
            mstore(add(oldRootPos, 0x20), newRoot)

            // store journal at `p`
            mstore(p, keccak256(p, add(batchSlotSize, 0x40)))

            // store journalDigest at `p`
            let ok := staticcall(gas(), 0x2, p, 0x20, p, 0x20)
            if iszero(ok) {
                revert(0, 0)
            }

            // store aggVerifierId at `p+0x20`
            mstore(add(p, 0x20), sload(aggVerifierId.slot))

            // pub inputs serialized
            mstore(p, keccak256(p, 0x40))

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
            let verifyOk := staticcall(
                gas(),
                sload(verifier.slot),
                add(p, 0x1c),
                0x1c4,
                0,
                0
            )
            if iszero(verifyOk) {
                revert(0, 0)
            }

            // update state - treeRoot
            sstore(treeRoot.slot, newRoot)
        }
    }

    function pubInputsHash(
        bytes32 combinedVKeyHash
    ) external view returns (bytes32) {
        bytes32 value;
        assembly {
            value := sload(combinedVKeyHash)
        }
        return value;
    }

    function setVerifier(address verifierAddress) external {
        if (msg.sender != owner) {
            revert("!owner");
        }
        verifier = verifierAddress;
    }

    function setAggVerifierid(bytes32 aggVerifierId_) external {
        if (msg.sender != owner) {
            revert("!owner");
        }
        aggVerifierId = aggVerifierId_;
    }

    // TODO: remove
    function setTreeRoot(bytes32 treeRoot_) external {
        if (msg.sender != owner) {
            revert("!owner");
        }
        treeRoot = treeRoot_;
    }
}
