// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

library ZkvmVerifier {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE_SUPER_ROOT_VERIFIED = 0x55a22a85;

    /// @param position encodes the position of each proof elements (left/right)
    /// @param proof array of proof elements
    struct MerkleProof {
        uint256 position;
        bytes32[] proof;
    }

    /// @notice Check if your public inputs are aggregated by Quantum
    /// @param merkleProof The inclusion proof for your public inputs
    /// @param circuitHash The value obtained during your circuit registration on Quantum
    /// @param quantumVerifier The address to the Quantum contract
    /// @param pubInputs Your public inputs
    function verifyPubInputs(
        MerkleProof calldata merkleProof,
        bytes32 circuitHash,
        address quantumVerifier,
        bytes calldata pubInputs
    ) internal view {
        assembly {
            let p := mload(0x40)

            // ** compute leaf = keccak(circuitHash || keccak(pubInputs)) **
            // keccak(pubInputs))
            let pubInputsSize := calldataload(0xc4) // public inputs size in bytes
            calldatacopy(p, 0xe4, pubInputsSize)
            mstore(add(p, 0x20), keccak256(p, pubInputsSize))

            // circuitHash
            mstore(p, circuitHash)

            // storing leaf at p+0x40; all earlier data at any memory can be discarded
            mstore(add(p, 0x40), keccak256(p, 0x40))

            mstore(p, calldataload(0x44)) // load merkle-proof-position at `p`

            // ** computing root (at `p+0x40`) using the proof elms and their position **
            let proofElmsSlotSize := mul(calldataload(0x84), 0x20)
            for {
                let x := 0
            } lt(x, proofElmsSlotSize) {
                x := add(x, 0x20)
            } {
                switch and(mload(p), ONE)
                case 1 {
                    mstore(add(p, 0x60), calldataload(add(0xa4, x)))
                    mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
                }
                default {
                    mstore(add(p, 0x20), calldataload(add(0xa4, x)))
                    mstore(add(p, 0x40), keccak256(add(p, 0x20), 0x40))
                }
                mstore(p, shr(1, mload(p))) // update next position
            }

            mstore(add(p, 0x20), SIGNATURE_SUPER_ROOT_VERIFIED)
            let ok := staticcall(
                gas(),
                quantumVerifier,
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
