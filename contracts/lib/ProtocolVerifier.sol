// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

library ProtocolVerifier_1 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE_SUPER_ROOT_VERIFIED = 0x55a22a85;

    /// @notice Check if your public inputs are aggregated by Quantum
    /// @param pubInputs Your public inputs
    /// @param merkleProofPosition The position of each merkle proof element (left/right) encoded as a single number
    /// @param merkleProof The inclusion proof for your public inputs
    /// @param combinedVKeyHash The value obtained during your circuit registration on Quantum
    /// @param quantumVerifier The address to the Quantum contract
    function verifyPubInputs(
        uint256[1] calldata pubInputs,
        uint256 merkleProofPosition,
        bytes32[] calldata merkleProof,
        bytes32 combinedVKeyHash,
        address quantumVerifier
    ) internal view {
        assembly {
            let p := mload(0x40)

            // ** compute leaf = keccak(combinedVKeyHash || keccak(pubInputs)) **
            // store pub inputs
            mstore(p, calldataload(0x4))

            // keccak(pubInputs))
            mstore(add(p, 0x20), keccak256(p, 0x20))

            // combinedVKeyHash
            mstore(p, combinedVKeyHash)

            // storing leaf at p+0x40; all earlier data at any memory can be discarded
            mstore(add(p, 0x40), keccak256(p, 0x40))

            mstore(p, calldataload(0x24)) // load merkle-proof-position at `p`

            // ** computing root (at `p+0x40`) using the proof elms and their position **
            let proofElmsSlotSize := mul(calldataload(0x64), 0x20)
            for {
                let x := 0
            } lt(x, proofElmsSlotSize) {
                x := add(x, 0x20)
            } {
                switch and(mload(p), ONE)
                case 1 {
                    mstore(add(p, 0x60), calldataload(add(0x84, x)))
                    mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
                }
                default {
                    mstore(add(p, 0x20), calldataload(add(0x84, x)))
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

library ProtocolVerifier_2 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE_SUPER_ROOT_VERIFIED = 0x55a22a85;

    /// @notice Check if your public inputs are aggregated by Quantum
    /// @param pubInputs Your public inputs
    /// @param merkleProofPosition The position of each merkle proof element (left/right) encoded as a single number
    /// @param merkleProof The inclusion proof for your public inputs
    /// @param combinedVKeyHash The value obtained during your circuit registration on Quantum
    /// @param quantumVerifier The address to the Quantum contract
    function verifyPubInputs(
        uint256[2] calldata pubInputs,
        uint256 merkleProofPosition,
        bytes32[] calldata merkleProof,
        bytes32 combinedVKeyHash,
        address quantumVerifier
    ) internal view {
        assembly {
            let p := mload(0x40)

            // ** compute leaf = keccak(combinedVKeyHash || keccak(pubInputs)) **
            // store pub inputs
            mstore(p, calldataload(0x4))
            mstore(add(p, 0x20), calldataload(0x24))

            // keccak(pubInputs))
            mstore(add(p, 0x20), keccak256(p, 0x40))

            // combinedVKeyHash
            mstore(p, combinedVKeyHash)

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

library ProtocolVerifier_3 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE_SUPER_ROOT_VERIFIED = 0x55a22a85;

    /// @notice Check if your public inputs are aggregated by Quantum
    /// @param pubInputs Your public inputs
    /// @param merkleProofPosition The position of each merkle proof element (left/right) encoded as a single number
    /// @param merkleProof The inclusion proof for your public inputs
    /// @param combinedVKeyHash The value obtained during your circuit registration on Quantum
    /// @param quantumVerifier The address to the Quantum contract
    function verifyPubInputs(
        uint256[3] calldata pubInputs,
        uint256 merkleProofPosition,
        bytes32[] calldata merkleProof,
        bytes32 combinedVKeyHash,
        address quantumVerifier
    ) internal view {
        assembly {
            let p := mload(0x40)

            // ** compute leaf = keccak(combinedVKeyHash || keccak(pubInputs)) **
            // store pub inputs
            mstore(p, calldataload(0x4))
            mstore(add(p, 0x20), calldataload(0x24))
            mstore(add(p, 0x40), calldataload(0x44))

            // keccak(pubInputs))
            mstore(add(p, 0x20), keccak256(p, 0x60))

            // combinedVKeyHash
            mstore(p, combinedVKeyHash)

            // storing leaf at p+0x40; all earlier data at any memory can be discarded
            mstore(add(p, 0x40), keccak256(p, 0x40))

            mstore(p, calldataload(0x64)) // load merkle-proof-position at `p`

            // ** computing root (at `p+0x40`) using the proof elms and their position **
            let proofElmsSlotSize := mul(calldataload(0xa4), 0x20)
            for {
                let x := 0
            } lt(x, proofElmsSlotSize) {
                x := add(x, 0x20)
            } {
                switch and(mload(p), ONE)
                case 1 {
                    mstore(add(p, 0x60), calldataload(add(0xc4, x)))
                    mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
                }
                default {
                    mstore(add(p, 0x20), calldataload(add(0xc4, x)))
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

library ProtocolVerifier_4 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE_SUPER_ROOT_VERIFIED = 0x55a22a85;

    /// @notice Check if your public inputs are aggregated by Quantum
    /// @param pubInputs Your public inputs
    /// @param merkleProofPosition The position of each merkle proof element (left/right) encoded as a single number
    /// @param merkleProof The inclusion proof for your public inputs
    /// @param combinedVKeyHash The value obtained during your circuit registration on Quantum
    /// @param quantumVerifier The address to the Quantum contract
    function verifyPubInputs(
        uint256[4] calldata pubInputs,
        uint256 merkleProofPosition,
        bytes32[] calldata merkleProof,
        bytes32 combinedVKeyHash,
        address quantumVerifier
    ) internal view {
        assembly {
            let p := mload(0x40)

            // ** compute leaf = keccak(combinedVKeyHash || keccak(pubInputs)) **
            // store pub inputs
            mstore(p, calldataload(0x4))
            mstore(add(p, 0x20), calldataload(0x24))
            mstore(add(p, 0x40), calldataload(0x44))
            mstore(add(p, 0x60), calldataload(0x64))

            // keccak(pubInputs))
            mstore(add(p, 0x20), keccak256(p, 0x80))

            // combinedVKeyHash
            mstore(p, combinedVKeyHash)

            // storing leaf at p+0x40; all earlier data at any memory can be discarded
            mstore(add(p, 0x40), keccak256(p, 0x40))

            mstore(p, calldataload(0x84)) // load merkle-proof-position at `p`

            // ** computing root (at `p+0x40`) using the proof elms and their position **
            let proofElmsSlotSize := mul(calldataload(0xc4), 0x20)
            for {
                let x := 0
            } lt(x, proofElmsSlotSize) {
                x := add(x, 0x20)
            } {
                switch and(mload(p), ONE)
                case 1 {
                    mstore(add(p, 0x60), calldataload(add(0xe4, x)))
                    mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
                }
                default {
                    mstore(add(p, 0x20), calldataload(add(0xe4, x)))
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

library ProtocolVerifier_5 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE_SUPER_ROOT_VERIFIED = 0x55a22a85;

    /// @notice Check if your public inputs are aggregated by Quantum
    /// @param pubInputs Your public inputs
    /// @param merkleProofPosition The position of each merkle proof element (left/right) encoded as a single number
    /// @param merkleProof The inclusion proof for your public inputs
    /// @param combinedVKeyHash The value obtained during your circuit registration on Quantum
    /// @param quantumVerifier The address to the Quantum contract
    function verifyPubInputs(
        uint256[5] calldata pubInputs,
        uint256 merkleProofPosition,
        bytes32[] calldata merkleProof,
        bytes32 combinedVKeyHash,
        address quantumVerifier
    ) internal view {
        assembly {
            let p := mload(0x40)

            // ** compute leaf = keccak(combinedVKeyHash || keccak(pubInputs)) **
            // store pub inputs
            mstore(p, calldataload(0x4))
            mstore(add(p, 0x20), calldataload(0x24))
            mstore(add(p, 0x40), calldataload(0x44))
            mstore(add(p, 0x60), calldataload(0x64))
            mstore(add(p, 0x80), calldataload(0x84))

            // keccak(pubInputs))
            mstore(add(p, 0x20), keccak256(p, 0xa0))

            // combinedVKeyHash
            mstore(p, combinedVKeyHash)

            // storing leaf at p+0x40; all earlier data at any memory can be discarded
            mstore(add(p, 0x40), keccak256(p, 0x40))

            mstore(p, calldataload(0xa4)) // load merkle-proof-position at `p`

            // ** computing root (at `p+0x40`) using the proof elms and their position **
            let proofElmsSlotSize := mul(calldataload(0xe4), 0x20)
            for {
                let x := 0
            } lt(x, proofElmsSlotSize) {
                x := add(x, 0x20)
            } {
                switch and(mload(p), ONE)
                case 1 {
                    mstore(add(p, 0x60), calldataload(add(0x104, x)))
                    mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
                }
                default {
                    mstore(add(p, 0x20), calldataload(add(0x104, x)))
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

library ProtocolVerifier_6 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE_SUPER_ROOT_VERIFIED = 0x55a22a85;

    /// @notice Check if your public inputs are aggregated by Quantum
    /// @param pubInputs Your public inputs
    /// @param merkleProofPosition The position of each merkle proof element (left/right) encoded as a single number
    /// @param merkleProof The inclusion proof for your public inputs
    /// @param combinedVKeyHash The value obtained during your circuit registration on Quantum
    /// @param quantumVerifier The address to the Quantum contract
    function verifyPubInputs(
        uint256[6] calldata pubInputs,
        uint256 merkleProofPosition,
        bytes32[] calldata merkleProof,
        bytes32 combinedVKeyHash,
        address quantumVerifier
    ) internal view {
        assembly {
            let p := mload(0x40)

            // ** compute leaf = keccak(combinedVKeyHash || keccak(pubInputs)) **
            // store pub inputs
            mstore(p, calldataload(0x4))
            mstore(add(p, 0x20), calldataload(0x24))
            mstore(add(p, 0x40), calldataload(0x44))
            mstore(add(p, 0x60), calldataload(0x64))
            mstore(add(p, 0x80), calldataload(0x84))
            mstore(add(p, 0xa0), calldataload(0xa4))

            // keccak(pubInputs))
            mstore(add(p, 0x20), keccak256(p, 0xc0))

            // combinedVKeyHash
            mstore(p, combinedVKeyHash)

            // storing leaf at p+0x40; all earlier data at any memory can be discarded
            mstore(add(p, 0x40), keccak256(p, 0x40))

            mstore(p, calldataload(0xc4)) // load merkle-proof-position at `p`

            // ** computing root (at `p+0x40`) using the proof elms and their position **
            let proofElmsSlotSize := mul(calldataload(0x104), 0x20)
            for {
                let x := 0
            } lt(x, proofElmsSlotSize) {
                x := add(x, 0x20)
            } {
                switch and(mload(p), ONE)
                case 1 {
                    mstore(add(p, 0x60), calldataload(add(0x124, x)))
                    mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
                }
                default {
                    mstore(add(p, 0x20), calldataload(add(0x124, x)))
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

library ProtocolVerifier_7 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE_SUPER_ROOT_VERIFIED = 0x55a22a85;

    /// @notice Check if your public inputs are aggregated by Quantum
    /// @param pubInputs Your public inputs
    /// @param merkleProofPosition The position of each merkle proof element (left/right) encoded as a single number
    /// @param merkleProof The inclusion proof for your public inputs
    /// @param combinedVKeyHash The value obtained during your circuit registration on Quantum
    /// @param quantumVerifier The address to the Quantum contract
    function verifyPubInputs(
        uint256[7] calldata pubInputs,
        uint256 merkleProofPosition,
        bytes32[] calldata merkleProof,
        bytes32 combinedVKeyHash,
        address quantumVerifier
    ) internal view {
        assembly {
            let p := mload(0x40)

            // ** compute leaf = keccak(combinedVKeyHash || keccak(pubInputs)) **
            // store pub inputs
            mstore(p, calldataload(0x4))
            mstore(add(p, 0x20), calldataload(0x24))
            mstore(add(p, 0x40), calldataload(0x44))
            mstore(add(p, 0x60), calldataload(0x64))
            mstore(add(p, 0x80), calldataload(0x84))
            mstore(add(p, 0xa0), calldataload(0xa4))
            mstore(add(p, 0xc0), calldataload(0xc4))

            // keccak(pubInputs))
            mstore(add(p, 0x20), keccak256(p, 0xe0))

            // combinedVKeyHash
            mstore(p, combinedVKeyHash)

            // storing leaf at p+0x40; all earlier data at any memory can be discarded
            mstore(add(p, 0x40), keccak256(p, 0x40))

            mstore(p, calldataload(0xe4)) // load merkle-proof-position at `p`

            // ** computing root (at `p+0x40`) using the proof elms and their position **
            let proofElmsSlotSize := mul(calldataload(0x124), 0x20)
            for {
                let x := 0
            } lt(x, proofElmsSlotSize) {
                x := add(x, 0x20)
            } {
                switch and(mload(p), ONE)
                case 1 {
                    mstore(add(p, 0x60), calldataload(add(0x144, x)))
                    mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
                }
                default {
                    mstore(add(p, 0x20), calldataload(add(0x144, x)))
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

library ProtocolVerifier_8 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE_SUPER_ROOT_VERIFIED = 0x55a22a85;

    /// @notice Check if your public inputs are aggregated by Quantum
    /// @param pubInputs Your public inputs
    /// @param merkleProofPosition The position of each merkle proof element (left/right) encoded as a single number
    /// @param merkleProof The inclusion proof for your public inputs
    /// @param combinedVKeyHash The value obtained during your circuit registration on Quantum
    /// @param quantumVerifier The address to the Quantum contract
    function verifyPubInputs(
        uint256[8] calldata pubInputs,
        uint256 merkleProofPosition,
        bytes32[] calldata merkleProof,
        bytes32 combinedVKeyHash,
        address quantumVerifier
    ) internal view {
        assembly {
            let p := mload(0x40)

            // ** compute leaf = keccak(combinedVKeyHash || keccak(pubInputs)) **
            // store pub inputs
            mstore(p, calldataload(0x4))
            mstore(add(p, 0x20), calldataload(0x24))
            mstore(add(p, 0x40), calldataload(0x44))
            mstore(add(p, 0x60), calldataload(0x64))
            mstore(add(p, 0x80), calldataload(0x84))
            mstore(add(p, 0xa0), calldataload(0xa4))
            mstore(add(p, 0xc0), calldataload(0xc4))
            mstore(add(p, 0xe0), calldataload(0xe4))

            // keccak(pubInputs))
            mstore(add(p, 0x20), keccak256(p, 0x100))

            // combinedVKeyHash
            mstore(p, combinedVKeyHash)

            // storing leaf at p+0x40; all earlier data at any memory can be discarded
            mstore(add(p, 0x40), keccak256(p, 0x40))

            mstore(p, calldataload(0x104)) // load merkle-proof-position at `p`

            // ** computing root (at `p+0x40`) using the proof elms and their position **
            let proofElmsSlotSize := mul(calldataload(0x144), 0x20)
            for {
                let x := 0
            } lt(x, proofElmsSlotSize) {
                x := add(x, 0x20)
            } {
                switch and(mload(p), ONE)
                case 1 {
                    mstore(add(p, 0x60), calldataload(add(0x164, x)))
                    mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
                }
                default {
                    mstore(add(p, 0x20), calldataload(add(0x164, x)))
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

library ProtocolVerifier_9 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE_SUPER_ROOT_VERIFIED = 0x55a22a85;

    /// @notice Check if your public inputs are aggregated by Quantum
    /// @param pubInputs Your public inputs
    /// @param merkleProofPosition The position of each merkle proof element (left/right) encoded as a single number
    /// @param merkleProof The inclusion proof for your public inputs
    /// @param combinedVKeyHash The value obtained during your circuit registration on Quantum
    /// @param quantumVerifier The address to the Quantum contract
    function verifyPubInputs(
        uint256[9] calldata pubInputs,
        uint256 merkleProofPosition,
        bytes32[] calldata merkleProof,
        bytes32 combinedVKeyHash,
        address quantumVerifier
    ) internal view {
        assembly {
            let p := mload(0x40)

            // ** compute leaf = keccak(combinedVKeyHash || keccak(pubInputs)) **
            // store pub inputs
            mstore(p, calldataload(0x4))
            mstore(add(p, 0x20), calldataload(0x24))
            mstore(add(p, 0x40), calldataload(0x44))
            mstore(add(p, 0x60), calldataload(0x64))
            mstore(add(p, 0x80), calldataload(0x84))
            mstore(add(p, 0xa0), calldataload(0xa4))
            mstore(add(p, 0xc0), calldataload(0xc4))
            mstore(add(p, 0xe0), calldataload(0xe4))
            mstore(add(p, 0x100), calldataload(0x104))

            // keccak(pubInputs))
            mstore(add(p, 0x20), keccak256(p, 0x120))

            // combinedVKeyHash
            mstore(p, combinedVKeyHash)

            // storing leaf at p+0x40; all earlier data at any memory can be discarded
            mstore(add(p, 0x40), keccak256(p, 0x40))

            mstore(p, calldataload(0x124)) // load merkle-proof-position at `p`

            // ** computing root (at `p+0x40`) using the proof elms and their position **
            let proofElmsSlotSize := mul(calldataload(0x164), 0x20)
            for {
                let x := 0
            } lt(x, proofElmsSlotSize) {
                x := add(x, 0x20)
            } {
                switch and(mload(p), ONE)
                case 1 {
                    mstore(add(p, 0x60), calldataload(add(0x184, x)))
                    mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
                }
                default {
                    mstore(add(p, 0x20), calldataload(add(0x184, x)))
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

library ProtocolVerifier_10 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE_SUPER_ROOT_VERIFIED = 0x55a22a85;

    /// @notice Check if your public inputs are aggregated by Quantum
    /// @param pubInputs Your public inputs
    /// @param merkleProofPosition The position of each merkle proof element (left/right) encoded as a single number
    /// @param merkleProof The inclusion proof for your public inputs
    /// @param combinedVKeyHash The value obtained during your circuit registration on Quantum
    /// @param quantumVerifier The address to the Quantum contract
    function verifyPubInputs(
        uint256[10] calldata pubInputs,
        uint256 merkleProofPosition,
        bytes32[] calldata merkleProof,
        bytes32 combinedVKeyHash,
        address quantumVerifier
    ) internal view {
        assembly {
            let p := mload(0x40)

            // ** compute leaf = keccak(combinedVKeyHash || keccak(pubInputs)) **
            // store pub inputs
            mstore(p, calldataload(0x4))
            mstore(add(p, 0x20), calldataload(0x24))
            mstore(add(p, 0x40), calldataload(0x44))
            mstore(add(p, 0x60), calldataload(0x64))
            mstore(add(p, 0x80), calldataload(0x84))
            mstore(add(p, 0xa0), calldataload(0xa4))
            mstore(add(p, 0xc0), calldataload(0xc4))
            mstore(add(p, 0xe0), calldataload(0xe4))
            mstore(add(p, 0x100), calldataload(0x104))
            mstore(add(p, 0x120), calldataload(0x124))

            // keccak(pubInputs))
            mstore(add(p, 0x20), keccak256(p, 0x140))

            // combinedVKeyHash
            mstore(p, combinedVKeyHash)

            // storing leaf at p+0x40; all earlier data at any memory can be discarded
            mstore(add(p, 0x40), keccak256(p, 0x40))

            mstore(p, calldataload(0x144)) // load merkle-proof-position at `p`

            // ** computing root (at `p+0x40`) using the proof elms and their position **
            let proofElmsSlotSize := mul(calldataload(0x184), 0x20)
            for {
                let x := 0
            } lt(x, proofElmsSlotSize) {
                x := add(x, 0x20)
            } {
                switch and(mload(p), ONE)
                case 1 {
                    mstore(add(p, 0x60), calldataload(add(0x1a4, x)))
                    mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
                }
                default {
                    mstore(add(p, 0x20), calldataload(add(0x1a4, x)))
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

library ProtocolVerifier_11 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE_SUPER_ROOT_VERIFIED = 0x55a22a85;

    /// @notice Check if your public inputs are aggregated by Quantum
    /// @param pubInputs Your public inputs
    /// @param merkleProofPosition The position of each merkle proof element (left/right) encoded as a single number
    /// @param merkleProof The inclusion proof for your public inputs
    /// @param combinedVKeyHash The value obtained during your circuit registration on Quantum
    /// @param quantumVerifier The address to the Quantum contract
    function verifyPubInputs(
        uint256[11] calldata pubInputs,
        uint256 merkleProofPosition,
        bytes32[] calldata merkleProof,
        bytes32 combinedVKeyHash,
        address quantumVerifier
    ) internal view {
        assembly {
            let p := mload(0x40)

            // ** compute leaf = keccak(combinedVKeyHash || keccak(pubInputs)) **
            // store pub inputs
            mstore(p, calldataload(0x4))
            mstore(add(p, 0x20), calldataload(0x24))
            mstore(add(p, 0x40), calldataload(0x44))
            mstore(add(p, 0x60), calldataload(0x64))
            mstore(add(p, 0x80), calldataload(0x84))
            mstore(add(p, 0xa0), calldataload(0xa4))
            mstore(add(p, 0xc0), calldataload(0xc4))
            mstore(add(p, 0xe0), calldataload(0xe4))
            mstore(add(p, 0x100), calldataload(0x104))
            mstore(add(p, 0x120), calldataload(0x124))
            mstore(add(p, 0x140), calldataload(0x144))

            // keccak(pubInputs))
            mstore(add(p, 0x20), keccak256(p, 0x160))

            // combinedVKeyHash
            mstore(p, combinedVKeyHash)

            // storing leaf at p+0x40; all earlier data at any memory can be discarded
            mstore(add(p, 0x40), keccak256(p, 0x40))

            mstore(p, calldataload(0x164)) // load merkle-proof-position at `p`

            // ** computing root (at `p+0x40`) using the proof elms and their position **
            let proofElmsSlotSize := mul(calldataload(0x1a4), 0x20)
            for {
                let x := 0
            } lt(x, proofElmsSlotSize) {
                x := add(x, 0x20)
            } {
                switch and(mload(p), ONE)
                case 1 {
                    mstore(add(p, 0x60), calldataload(add(0x1c4, x)))
                    mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
                }
                default {
                    mstore(add(p, 0x20), calldataload(add(0x1c4, x)))
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

library ProtocolVerifier_12 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE_SUPER_ROOT_VERIFIED = 0x55a22a85;

    /// @notice Check if your public inputs are aggregated by Quantum
    /// @param pubInputs Your public inputs
    /// @param merkleProofPosition The position of each merkle proof element (left/right) encoded as a single number
    /// @param merkleProof The inclusion proof for your public inputs
    /// @param combinedVKeyHash The value obtained during your circuit registration on Quantum
    /// @param quantumVerifier The address to the Quantum contract
    function verifyPubInputs(
        uint256[12] calldata pubInputs,
        uint256 merkleProofPosition,
        bytes32[] calldata merkleProof,
        bytes32 combinedVKeyHash,
        address quantumVerifier
    ) internal view {
        assembly {
            let p := mload(0x40)

            // ** compute leaf = keccak(combinedVKeyHash || keccak(pubInputs)) **
            // store pub inputs
            mstore(p, calldataload(0x4))
            mstore(add(p, 0x20), calldataload(0x24))
            mstore(add(p, 0x40), calldataload(0x44))
            mstore(add(p, 0x60), calldataload(0x64))
            mstore(add(p, 0x80), calldataload(0x84))
            mstore(add(p, 0xa0), calldataload(0xa4))
            mstore(add(p, 0xc0), calldataload(0xc4))
            mstore(add(p, 0xe0), calldataload(0xe4))
            mstore(add(p, 0x100), calldataload(0x104))
            mstore(add(p, 0x120), calldataload(0x124))
            mstore(add(p, 0x140), calldataload(0x144))
            mstore(add(p, 0x160), calldataload(0x164))

            // keccak(pubInputs))
            mstore(add(p, 0x20), keccak256(p, 0x180))

            // combinedVKeyHash
            mstore(p, combinedVKeyHash)

            // storing leaf at p+0x40; all earlier data at any memory can be discarded
            mstore(add(p, 0x40), keccak256(p, 0x40))

            mstore(p, calldataload(0x184)) // load merkle-proof-position at `p`

            // ** computing root (at `p+0x40`) using the proof elms and their position **
            let proofElmsSlotSize := mul(calldataload(0x1c4), 0x20)
            for {
                let x := 0
            } lt(x, proofElmsSlotSize) {
                x := add(x, 0x20)
            } {
                switch and(mload(p), ONE)
                case 1 {
                    mstore(add(p, 0x60), calldataload(add(0x1e4, x)))
                    mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
                }
                default {
                    mstore(add(p, 0x20), calldataload(add(0x1e4, x)))
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

library ProtocolVerifier_13 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE_SUPER_ROOT_VERIFIED = 0x55a22a85;

    /// @notice Check if your public inputs are aggregated by Quantum
    /// @param pubInputs Your public inputs
    /// @param merkleProofPosition The position of each merkle proof element (left/right) encoded as a single number
    /// @param merkleProof The inclusion proof for your public inputs
    /// @param combinedVKeyHash The value obtained during your circuit registration on Quantum
    /// @param quantumVerifier The address to the Quantum contract
    function verifyPubInputs(
        uint256[13] calldata pubInputs,
        uint256 merkleProofPosition,
        bytes32[] calldata merkleProof,
        bytes32 combinedVKeyHash,
        address quantumVerifier
    ) internal view {
        assembly {
            let p := mload(0x40)

            // ** compute leaf = keccak(combinedVKeyHash || keccak(pubInputs)) **
            // store pub inputs
            mstore(p, calldataload(0x4))
            mstore(add(p, 0x20), calldataload(0x24))
            mstore(add(p, 0x40), calldataload(0x44))
            mstore(add(p, 0x60), calldataload(0x64))
            mstore(add(p, 0x80), calldataload(0x84))
            mstore(add(p, 0xa0), calldataload(0xa4))
            mstore(add(p, 0xc0), calldataload(0xc4))
            mstore(add(p, 0xe0), calldataload(0xe4))
            mstore(add(p, 0x100), calldataload(0x104))
            mstore(add(p, 0x120), calldataload(0x124))
            mstore(add(p, 0x140), calldataload(0x144))
            mstore(add(p, 0x160), calldataload(0x164))
            mstore(add(p, 0x180), calldataload(0x184))

            // keccak(pubInputs))
            mstore(add(p, 0x20), keccak256(p, 0x1a0))

            // combinedVKeyHash
            mstore(p, combinedVKeyHash)

            // storing leaf at p+0x40; all earlier data at any memory can be discarded
            mstore(add(p, 0x40), keccak256(p, 0x40))

            mstore(p, calldataload(0x1a4)) // load merkle-proof-position at `p`

            // ** computing root (at `p+0x40`) using the proof elms and their position **
            let proofElmsSlotSize := mul(calldataload(0x1e4), 0x20)
            for {
                let x := 0
            } lt(x, proofElmsSlotSize) {
                x := add(x, 0x20)
            } {
                switch and(mload(p), ONE)
                case 1 {
                    mstore(add(p, 0x60), calldataload(add(0x204, x)))
                    mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
                }
                default {
                    mstore(add(p, 0x20), calldataload(add(0x204, x)))
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

library ProtocolVerifier_14 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE_SUPER_ROOT_VERIFIED = 0x55a22a85;

    /// @notice Check if your public inputs are aggregated by Quantum
    /// @param pubInputs Your public inputs
    /// @param merkleProofPosition The position of each merkle proof element (left/right) encoded as a single number
    /// @param merkleProof The inclusion proof for your public inputs
    /// @param combinedVKeyHash The value obtained during your circuit registration on Quantum
    /// @param quantumVerifier The address to the Quantum contract
    function verifyPubInputs(
        uint256[14] calldata pubInputs,
        uint256 merkleProofPosition,
        bytes32[] calldata merkleProof,
        bytes32 combinedVKeyHash,
        address quantumVerifier
    ) internal view {
        assembly {
            let p := mload(0x40)

            // ** compute leaf = keccak(combinedVKeyHash || keccak(pubInputs)) **
            // store pub inputs
            mstore(p, calldataload(0x4))
            mstore(add(p, 0x20), calldataload(0x24))
            mstore(add(p, 0x40), calldataload(0x44))
            mstore(add(p, 0x60), calldataload(0x64))
            mstore(add(p, 0x80), calldataload(0x84))
            mstore(add(p, 0xa0), calldataload(0xa4))
            mstore(add(p, 0xc0), calldataload(0xc4))
            mstore(add(p, 0xe0), calldataload(0xe4))
            mstore(add(p, 0x100), calldataload(0x104))
            mstore(add(p, 0x120), calldataload(0x124))
            mstore(add(p, 0x140), calldataload(0x144))
            mstore(add(p, 0x160), calldataload(0x164))
            mstore(add(p, 0x180), calldataload(0x184))
            mstore(add(p, 0x1a0), calldataload(0x1a4))

            // keccak(pubInputs))
            mstore(add(p, 0x20), keccak256(p, 0x1c0))

            // combinedVKeyHash
            mstore(p, combinedVKeyHash)

            // storing leaf at p+0x40; all earlier data at any memory can be discarded
            mstore(add(p, 0x40), keccak256(p, 0x40))

            mstore(p, calldataload(0x1c4)) // load merkle-proof-position at `p`

            // ** computing root (at `p+0x40`) using the proof elms and their position **
            let proofElmsSlotSize := mul(calldataload(0x204), 0x20)
            for {
                let x := 0
            } lt(x, proofElmsSlotSize) {
                x := add(x, 0x20)
            } {
                switch and(mload(p), ONE)
                case 1 {
                    mstore(add(p, 0x60), calldataload(add(0x224, x)))
                    mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
                }
                default {
                    mstore(add(p, 0x20), calldataload(add(0x224, x)))
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

library ProtocolVerifier_15 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE_SUPER_ROOT_VERIFIED = 0x55a22a85;

    /// @notice Check if your public inputs are aggregated by Quantum
    /// @param pubInputs Your public inputs
    /// @param merkleProofPosition The position of each merkle proof element (left/right) encoded as a single number
    /// @param merkleProof The inclusion proof for your public inputs
    /// @param combinedVKeyHash The value obtained during your circuit registration on Quantum
    /// @param quantumVerifier The address to the Quantum contract
    function verifyPubInputs(
        uint256[15] calldata pubInputs,
        uint256 merkleProofPosition,
        bytes32[] calldata merkleProof,
        bytes32 combinedVKeyHash,
        address quantumVerifier
    ) internal view {
        assembly {
            let p := mload(0x40)

            // ** compute leaf = keccak(combinedVKeyHash || keccak(pubInputs)) **
            // store pub inputs
            mstore(p, calldataload(0x4))
            mstore(add(p, 0x20), calldataload(0x24))
            mstore(add(p, 0x40), calldataload(0x44))
            mstore(add(p, 0x60), calldataload(0x64))
            mstore(add(p, 0x80), calldataload(0x84))
            mstore(add(p, 0xa0), calldataload(0xa4))
            mstore(add(p, 0xc0), calldataload(0xc4))
            mstore(add(p, 0xe0), calldataload(0xe4))
            mstore(add(p, 0x100), calldataload(0x104))
            mstore(add(p, 0x120), calldataload(0x124))
            mstore(add(p, 0x140), calldataload(0x144))
            mstore(add(p, 0x160), calldataload(0x164))
            mstore(add(p, 0x180), calldataload(0x184))
            mstore(add(p, 0x1a0), calldataload(0x1a4))
            mstore(add(p, 0x1c0), calldataload(0x1c4))

            // keccak(pubInputs))
            mstore(add(p, 0x20), keccak256(p, 0x1e0))

            // combinedVKeyHash
            mstore(p, combinedVKeyHash)

            // storing leaf at p+0x40; all earlier data at any memory can be discarded
            mstore(add(p, 0x40), keccak256(p, 0x40))

            mstore(p, calldataload(0x1e4)) // load merkle-proof-position at `p`

            // ** computing root (at `p+0x40`) using the proof elms and their position **
            let proofElmsSlotSize := mul(calldataload(0x224), 0x20)
            for {
                let x := 0
            } lt(x, proofElmsSlotSize) {
                x := add(x, 0x20)
            } {
                switch and(mload(p), ONE)
                case 1 {
                    mstore(add(p, 0x60), calldataload(add(0x244, x)))
                    mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
                }
                default {
                    mstore(add(p, 0x20), calldataload(add(0x244, x)))
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
