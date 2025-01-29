// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

library CircuitVerifier {
    uint256 private constant ONE = 0x01;
    uint256 private constant SIGNATURE_SUPER_ROOT_VERIFIED = 0x55a22a85;

    /// @param position Encodes the position of each proof elements (left/right)
    /// @param elms Array of proof elements
    struct MerkleProof {
        uint256 position;
        bytes32[] elms;
    }

    /// @notice Check if your public inputs are aggregated by Quantum
    /// @dev @param merkleProof This must be the first calldata parameter in the caller function
    /// @param merkleProof The inclusion proof for your public inputs
    /// @param pubInputsHash Keccak256 has of your public inputs
    /// @param circuitHash The value obtained during your circuit registration on Quantum
    /// @param quantumVerifier The address to the Quantum contract
    function verifyPubInputs(
        MerkleProof calldata merkleProof,
        bytes32 pubInputsHash,
        bytes32 circuitHash,
        address quantumVerifier
    ) internal view {
        assembly {
            let p := mload(0x40)

            // ** compute leaf = keccak(circuitHash || keccak(pubInputs)) **
            // circuitHash
            mstore(p, circuitHash)

            // store pub inputs hash
            mstore(add(p, 0x20), pubInputsHash)

            // storing leaf at p+0x40
            mstore(add(p, 0x40), keccak256(p, 0x40))

            // merkle proof location
            let merkleProofLoc := add(0x4, calldataload(0x4))
            let proofElmsLoc := add(
                merkleProofLoc,
                calldataload(add(merkleProofLoc, 0x20))
            )

            mstore(p, calldataload(merkleProofLoc)) // load merkle-proof-position at `p`

            // ** computing root (at `p+0x40`) using the proof and their position **
            let merkleProofElmsSlotSize := mul(calldataload(proofElmsLoc), 0x20)
            let firstProofLoc := add(proofElmsLoc, 0x20)
            for {
                let x := 0
            } lt(x, merkleProofElmsSlotSize) {
                x := add(x, 0x20)
            } {
                switch and(mload(p), ONE)
                case 1 {
                    mstore(add(p, 0x60), calldataload(add(firstProofLoc, x)))
                    mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
                }
                default {
                    mstore(add(p, 0x20), calldataload(add(firstProofLoc, x)))
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
            if iszero(ok) {
                revert(0, 0)
            }
            if iszero(eq(mload(p), ONE)) {
                revert(0, 0)
            }
        }
    }
}