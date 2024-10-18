// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {IQuantum} from "./interfaces/IQuantum.sol";

contract Quantum {
    uint256 constant SIGNATURE = 0xb2ff0a36;

    bytes32 private aggVerifierId;
    address public owner;
    address public verifier;

    mapping(bytes32 => bool) superproofRootVerified;

    struct Proof {
        uint256[8] proof;
        uint256[2] commitments;
        uint256[2] commitmentPok;
    }

    constructor(address verifier_, bytes32 aggVerifierId_) {
        owner = msg.sender;
        verifier = verifier_;
        aggVerifierId = aggVerifierId_;
    }

    function verifySuperproof(
        Proof calldata proof,
        bytes32 batchRoot
    ) external {
        assembly {
            let p := mload(0x40)

            // copy journal from calldata
            mstore(p, calldataload(0x184))

            // store aggVerifierId at `p+0x20`
            mstore(add(p, 0x20), sload(aggVerifierId.slot))

            // pub inputs serialized
            mstore(p, keccak256(p, 0x40))

            // store public inputs just after the proof in the next step
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
        }

        superproofRootVerified[batchRoot] = true;
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
}
