// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

library ProtocolVerifier_1 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE_PIS_HASHES = 0x70e8daf7;
    uint256 constant SIGNATURE_TREE_ROOT = 0x14dc6c14;

    struct ProtocolInclusionProof {
        uint256 merkleProofPosition;
        bytes32[10] merkleProof;
        bytes32 leafNextValue;
        bytes8 leafNextIdx;
    }

    function verifyLatestPubInputs(
        uint256[1] calldata pubInputs,
        bytes32 vkHash,
        address quantum_verifier
    ) internal view {
        assembly {
            let p := mload(0x40)
            let zero := mload(0x60)

            // store public inputs
            mstore(add(p, 0x40), calldataload(0x4))
            // extend public inputs
            mstore(add(p, 0x60), zero)
            mstore(add(p, 0x80), zero)
            mstore(add(p, 0xa0), zero)
            mstore(add(p, 0xc0), zero)
            mstore(add(p, 0xe0), zero)
            mstore(add(p, 0x100), zero)
            mstore(add(p, 0x120), zero)
            mstore(add(p, 0x140), zero)
            mstore(add(p, 0x160), zero)
            mstore(add(p, 0x180), zero)
            mstore(add(p, 0x1a0), zero)
            mstore(add(p, 0x1c0), zero)
            mstore(add(p, 0x1e0), zero)
            mstore(add(p, 0x200), zero)
            mstore(add(p, 0x220), zero)
            mstore(add(p, 0x240), zero)
            mstore(add(p, 0x260), zero)
            mstore(add(p, 0x280), zero)
            mstore(add(p, 0x2a0), zero)
            // public inputs hash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x280))

            // verify on quantum
            mstore(add(p, 0x20), vkHash)
            mstore(p, SIGNATURE_PIS_HASHES)
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

    function verifyOldPubInputs(
        ProtocolInclusionProof calldata protocolInclusionProof,
        uint256[1] calldata pubInputs,
        bytes32 vKeyHash,
        address quantum_verifier
    ) internal view {
        assembly {
            let p := mload(0x40)
            let zero := mload(0x60)

            // ** computer leaf value = keccak(vKeyHash || keccak(extend(pubInputs))) **
            // store pub inputs
            mstore(p, calldataload(0x1a4))
            // extend public inputs
            mstore(add(p, 0x20), zero)
            mstore(add(p, 0x40), zero)
            mstore(add(p, 0x60), zero)
            mstore(add(p, 0x80), zero)
            mstore(add(p, 0xa0), zero)
            mstore(add(p, 0xc0), zero)
            mstore(add(p, 0xe0), zero)
            mstore(add(p, 0x100), zero)
            mstore(add(p, 0x120), zero)
            mstore(add(p, 0x140), zero)
            mstore(add(p, 0x160), zero)
            mstore(add(p, 0x180), zero)
            mstore(add(p, 0x1a0), zero)
            mstore(add(p, 0x1c0), zero)
            mstore(add(p, 0x1e0), zero)
            mstore(add(p, 0x200), zero)
            mstore(add(p, 0x220), zero)
            mstore(add(p, 0x240), zero)
            mstore(add(p, 0x260), zero)

            // keccak(extend(pubInputs)))
            mstore(add(p, 0x20), keccak256(p, 0x280))

            // vKeyHash
            mstore(p, vKeyHash)

            // construct leaf
            mstore(add(p, 0x40), keccak256(p, 0x40)) // leaf value
            mstore(add(p, 0x60), calldataload(0x164)) // leaf next value
            mstore(add(p, 0x80), calldataload(0x184)) // leaf next idx

            // compute leafHash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x48)) //  storing leafHash at p+0x40; all earlier data at any memory can be discarded

            mstore(p, calldataload(0x4)) // load merkle-proof-position at `p`

            // computing root (at `p+0x40`) using 10 proof elms and their position
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

library ProtocolVerifier_2 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE_PIS_HASHES = 0x70e8daf7;
    uint256 constant SIGNATURE_TREE_ROOT = 0x14dc6c14;

    struct ProtocolInclusionProof {
        uint256 merkleProofPosition;
        bytes32[10] merkleProof;
        bytes32 leafNextValue;
        bytes8 leafNextIdx;
    }

    function verifyLatestPubInputs(
        uint256[2] calldata pubInputs,
        bytes32 vkHash,
        address quantum_verifier
    ) internal view {
        assembly {
            let p := mload(0x40)
            let zero := mload(0x60)

            // store public inputs
            mstore(add(p, 0x40), calldataload(0x4))
            mstore(add(p, 0x60), calldataload(0x24))
            // extend public inputs
            mstore(add(p, 0x80), zero)
            mstore(add(p, 0xa0), zero)
            mstore(add(p, 0xc0), zero)
            mstore(add(p, 0xe0), zero)
            mstore(add(p, 0x100), zero)
            mstore(add(p, 0x120), zero)
            mstore(add(p, 0x140), zero)
            mstore(add(p, 0x160), zero)
            mstore(add(p, 0x180), zero)
            mstore(add(p, 0x1a0), zero)
            mstore(add(p, 0x1c0), zero)
            mstore(add(p, 0x1e0), zero)
            mstore(add(p, 0x200), zero)
            mstore(add(p, 0x220), zero)
            mstore(add(p, 0x240), zero)
            mstore(add(p, 0x260), zero)
            mstore(add(p, 0x280), zero)
            mstore(add(p, 0x2a0), zero)
            // public inputs hash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x280))

            // verify on quantum
            mstore(add(p, 0x20), vkHash)
            mstore(p, SIGNATURE_PIS_HASHES)
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

    function verifyOldPubInputs(
        ProtocolInclusionProof calldata protocolInclusionProof,
        uint256[2] calldata pubInputs,
        bytes32 vKeyHash,
        address quantum_verifier
    ) internal view {
        assembly {
            let p := mload(0x40)
            let zero := mload(0x60)

            // ** computer leaf value = keccak(vKeyHash || keccak(extend(pubInputs))) **
            // store pub inputs
            mstore(p, calldataload(0x1a4))
            mstore(add(p, 0x20), calldataload(0x1c4))
            // extend public inputs
            mstore(add(p, 0x40), zero)
            mstore(add(p, 0x60), zero)
            mstore(add(p, 0x80), zero)
            mstore(add(p, 0xa0), zero)
            mstore(add(p, 0xc0), zero)
            mstore(add(p, 0xe0), zero)
            mstore(add(p, 0x100), zero)
            mstore(add(p, 0x120), zero)
            mstore(add(p, 0x140), zero)
            mstore(add(p, 0x160), zero)
            mstore(add(p, 0x180), zero)
            mstore(add(p, 0x1a0), zero)
            mstore(add(p, 0x1c0), zero)
            mstore(add(p, 0x1e0), zero)
            mstore(add(p, 0x200), zero)
            mstore(add(p, 0x220), zero)
            mstore(add(p, 0x240), zero)
            mstore(add(p, 0x260), zero)

            // keccak(extend(pubInputs)))
            mstore(add(p, 0x20), keccak256(p, 0x280))

            // vKeyHash
            mstore(p, vKeyHash)

            // construct leaf
            mstore(add(p, 0x40), keccak256(p, 0x40)) // leaf value
            mstore(add(p, 0x60), calldataload(0x164)) // leaf next value
            mstore(add(p, 0x80), calldataload(0x184)) // leaf next idx

            // compute leafHash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x48)) //  storing leafHash at p+0x40; all earlier data at any memory can be discarded

            mstore(p, calldataload(0x4)) // load merkle-proof-position at `p`

            // computing root (at `p+0x40`) using 10 proof elms and their position
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

library ProtocolVerifier_3 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE_PIS_HASHES = 0x70e8daf7;
    uint256 constant SIGNATURE_TREE_ROOT = 0x14dc6c14;

    struct ProtocolInclusionProof {
        uint256 merkleProofPosition;
        bytes32[10] merkleProof;
        bytes32 leafNextValue;
        bytes8 leafNextIdx;
    }

    function verifyLatestPubInputs(
        uint256[3] calldata pubInputs,
        bytes32 vkHash,
        address quantum_verifier
    ) internal view {
        assembly {
            let p := mload(0x40)
            let zero := mload(0x60)

            // store public inputs
            mstore(add(p, 0x40), calldataload(0x4))
            mstore(add(p, 0x60), calldataload(0x24))
            mstore(add(p, 0x80), calldataload(0x44))
            // extend public inputs
            mstore(add(p, 0xa0), zero)
            mstore(add(p, 0xc0), zero)
            mstore(add(p, 0xe0), zero)
            mstore(add(p, 0x100), zero)
            mstore(add(p, 0x120), zero)
            mstore(add(p, 0x140), zero)
            mstore(add(p, 0x160), zero)
            mstore(add(p, 0x180), zero)
            mstore(add(p, 0x1a0), zero)
            mstore(add(p, 0x1c0), zero)
            mstore(add(p, 0x1e0), zero)
            mstore(add(p, 0x200), zero)
            mstore(add(p, 0x220), zero)
            mstore(add(p, 0x240), zero)
            mstore(add(p, 0x260), zero)
            mstore(add(p, 0x280), zero)
            mstore(add(p, 0x2a0), zero)
            // public inputs hash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x280))

            // verify on quantum
            mstore(add(p, 0x20), vkHash)
            mstore(p, SIGNATURE_PIS_HASHES)
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

    function verifyOldPubInputs(
        ProtocolInclusionProof calldata protocolInclusionProof,
        uint256[3] calldata pubInputs,
        bytes32 vKeyHash,
        address quantum_verifier
    ) internal view {
        assembly {
            let p := mload(0x40)
            let zero := mload(0x60)

            // ** computer leaf value = keccak(vKeyHash || keccak(extend(pubInputs))) **
            // store pub inputs
            mstore(p, calldataload(0x1a4))
            mstore(add(p, 0x20), calldataload(0x1c4))
            mstore(add(p, 0x40), calldataload(0x1e4))
            // extend public inputs
            mstore(add(p, 0x60), zero)
            mstore(add(p, 0x80), zero)
            mstore(add(p, 0xa0), zero)
            mstore(add(p, 0xc0), zero)
            mstore(add(p, 0xe0), zero)
            mstore(add(p, 0x100), zero)
            mstore(add(p, 0x120), zero)
            mstore(add(p, 0x140), zero)
            mstore(add(p, 0x160), zero)
            mstore(add(p, 0x180), zero)
            mstore(add(p, 0x1a0), zero)
            mstore(add(p, 0x1c0), zero)
            mstore(add(p, 0x1e0), zero)
            mstore(add(p, 0x200), zero)
            mstore(add(p, 0x220), zero)
            mstore(add(p, 0x240), zero)
            mstore(add(p, 0x260), zero)

            // keccak(extend(pubInputs)))
            mstore(add(p, 0x20), keccak256(p, 0x280))

            // vKeyHash
            mstore(p, vKeyHash)

            // construct leaf
            mstore(add(p, 0x40), keccak256(p, 0x40)) // leaf value
            mstore(add(p, 0x60), calldataload(0x164)) // leaf next value
            mstore(add(p, 0x80), calldataload(0x184)) // leaf next idx

            // compute leafHash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x48)) //  storing leafHash at p+0x40; all earlier data at any memory can be discarded

            mstore(p, calldataload(0x4)) // load merkle-proof-position at `p`

            // computing root (at `p+0x40`) using 10 proof elms and their position
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

library ProtocolVerifier_4 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE_PIS_HASHES = 0x70e8daf7;
    uint256 constant SIGNATURE_TREE_ROOT = 0x14dc6c14;

    struct ProtocolInclusionProof {
        uint256 merkleProofPosition;
        bytes32[10] merkleProof;
        bytes32 leafNextValue;
        bytes8 leafNextIdx;
    }

    function verifyLatestPubInputs(
        uint256[4] calldata pubInputs,
        bytes32 vkHash,
        address quantum_verifier
    ) internal view {
        assembly {
            let p := mload(0x40)
            let zero := mload(0x60)

            // store public inputs
            mstore(add(p, 0x40), calldataload(0x4))
            mstore(add(p, 0x60), calldataload(0x24))
            mstore(add(p, 0x80), calldataload(0x44))
            mstore(add(p, 0xa0), calldataload(0x64))
            // extend public inputs
            mstore(add(p, 0xc0), zero)
            mstore(add(p, 0xe0), zero)
            mstore(add(p, 0x100), zero)
            mstore(add(p, 0x120), zero)
            mstore(add(p, 0x140), zero)
            mstore(add(p, 0x160), zero)
            mstore(add(p, 0x180), zero)
            mstore(add(p, 0x1a0), zero)
            mstore(add(p, 0x1c0), zero)
            mstore(add(p, 0x1e0), zero)
            mstore(add(p, 0x200), zero)
            mstore(add(p, 0x220), zero)
            mstore(add(p, 0x240), zero)
            mstore(add(p, 0x260), zero)
            mstore(add(p, 0x280), zero)
            mstore(add(p, 0x2a0), zero)
            // public inputs hash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x280))

            // verify on quantum
            mstore(add(p, 0x20), vkHash)
            mstore(p, SIGNATURE_PIS_HASHES)
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

    function verifyOldPubInputs(
        ProtocolInclusionProof calldata protocolInclusionProof,
        uint256[4] calldata pubInputs,
        bytes32 vKeyHash,
        address quantum_verifier
    ) internal view {
        assembly {
            let p := mload(0x40)
            let zero := mload(0x60)

            // ** computer leaf value = keccak(vKeyHash || keccak(extend(pubInputs))) **
            // store pub inputs
            mstore(p, calldataload(0x1a4))
            mstore(add(p, 0x20), calldataload(0x1c4))
            mstore(add(p, 0x40), calldataload(0x1e4))
            mstore(add(p, 0x60), calldataload(0x204))
            // extend public inputs
            mstore(add(p, 0x80), zero)
            mstore(add(p, 0xa0), zero)
            mstore(add(p, 0xc0), zero)
            mstore(add(p, 0xe0), zero)
            mstore(add(p, 0x100), zero)
            mstore(add(p, 0x120), zero)
            mstore(add(p, 0x140), zero)
            mstore(add(p, 0x160), zero)
            mstore(add(p, 0x180), zero)
            mstore(add(p, 0x1a0), zero)
            mstore(add(p, 0x1c0), zero)
            mstore(add(p, 0x1e0), zero)
            mstore(add(p, 0x200), zero)
            mstore(add(p, 0x220), zero)
            mstore(add(p, 0x240), zero)
            mstore(add(p, 0x260), zero)

            // keccak(extend(pubInputs)))
            mstore(add(p, 0x20), keccak256(p, 0x280))

            // vKeyHash
            mstore(p, vKeyHash)

            // construct leaf
            mstore(add(p, 0x40), keccak256(p, 0x40)) // leaf value
            mstore(add(p, 0x60), calldataload(0x164)) // leaf next value
            mstore(add(p, 0x80), calldataload(0x184)) // leaf next idx

            // compute leafHash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x48)) //  storing leafHash at p+0x40; all earlier data at any memory can be discarded

            mstore(p, calldataload(0x4)) // load merkle-proof-position at `p`

            // computing root (at `p+0x40`) using 10 proof elms and their position
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

library ProtocolVerifier_5 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE_PIS_HASHES = 0x70e8daf7;
    uint256 constant SIGNATURE_TREE_ROOT = 0x14dc6c14;

    struct ProtocolInclusionProof {
        uint256 merkleProofPosition;
        bytes32[10] merkleProof;
        bytes32 leafNextValue;
        bytes8 leafNextIdx;
    }

    function verifyLatestPubInputs(
        uint256[5] calldata pubInputs,
        bytes32 vkHash,
        address quantum_verifier
    ) internal view {
        assembly {
            let p := mload(0x40)
            let zero := mload(0x60)

            // store public inputs
            mstore(add(p, 0x40), calldataload(0x4))
            mstore(add(p, 0x60), calldataload(0x24))
            mstore(add(p, 0x80), calldataload(0x44))
            mstore(add(p, 0xa0), calldataload(0x64))
            mstore(add(p, 0xc0), calldataload(0x84))
            // extend public inputs
            mstore(add(p, 0xe0), zero)
            mstore(add(p, 0x100), zero)
            mstore(add(p, 0x120), zero)
            mstore(add(p, 0x140), zero)
            mstore(add(p, 0x160), zero)
            mstore(add(p, 0x180), zero)
            mstore(add(p, 0x1a0), zero)
            mstore(add(p, 0x1c0), zero)
            mstore(add(p, 0x1e0), zero)
            mstore(add(p, 0x200), zero)
            mstore(add(p, 0x220), zero)
            mstore(add(p, 0x240), zero)
            mstore(add(p, 0x260), zero)
            mstore(add(p, 0x280), zero)
            mstore(add(p, 0x2a0), zero)
            // public inputs hash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x280))

            // verify on quantum
            mstore(add(p, 0x20), vkHash)
            mstore(p, SIGNATURE_PIS_HASHES)
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

    function verifyOldPubInputs(
        ProtocolInclusionProof calldata protocolInclusionProof,
        uint256[5] calldata pubInputs,
        bytes32 vKeyHash,
        address quantum_verifier
    ) internal view {
        assembly {
            let p := mload(0x40)
            let zero := mload(0x60)

            // ** computer leaf value = keccak(vKeyHash || keccak(extend(pubInputs))) **
            // store pub inputs
            mstore(p, calldataload(0x1a4))
            mstore(add(p, 0x20), calldataload(0x1c4))
            mstore(add(p, 0x40), calldataload(0x1e4))
            mstore(add(p, 0x60), calldataload(0x204))
            mstore(add(p, 0x80), calldataload(0x224))
            // extend public inputs
            mstore(add(p, 0xa0), zero)
            mstore(add(p, 0xc0), zero)
            mstore(add(p, 0xe0), zero)
            mstore(add(p, 0x100), zero)
            mstore(add(p, 0x120), zero)
            mstore(add(p, 0x140), zero)
            mstore(add(p, 0x160), zero)
            mstore(add(p, 0x180), zero)
            mstore(add(p, 0x1a0), zero)
            mstore(add(p, 0x1c0), zero)
            mstore(add(p, 0x1e0), zero)
            mstore(add(p, 0x200), zero)
            mstore(add(p, 0x220), zero)
            mstore(add(p, 0x240), zero)
            mstore(add(p, 0x260), zero)

            // keccak(extend(pubInputs)))
            mstore(add(p, 0x20), keccak256(p, 0x280))

            // vKeyHash
            mstore(p, vKeyHash)

            // construct leaf
            mstore(add(p, 0x40), keccak256(p, 0x40)) // leaf value
            mstore(add(p, 0x60), calldataload(0x164)) // leaf next value
            mstore(add(p, 0x80), calldataload(0x184)) // leaf next idx

            // compute leafHash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x48)) //  storing leafHash at p+0x40; all earlier data at any memory can be discarded

            mstore(p, calldataload(0x4)) // load merkle-proof-position at `p`

            // computing root (at `p+0x40`) using 10 proof elms and their position
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

library ProtocolVerifier_6 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE_PIS_HASHES = 0x70e8daf7;
    uint256 constant SIGNATURE_TREE_ROOT = 0x14dc6c14;

    struct ProtocolInclusionProof {
        uint256 merkleProofPosition;
        bytes32[10] merkleProof;
        bytes32 leafNextValue;
        bytes8 leafNextIdx;
    }

    function verifyLatestPubInputs(
        uint256[6] calldata pubInputs,
        bytes32 vkHash,
        address quantum_verifier
    ) internal view {
        assembly {
            let p := mload(0x40)
            let zero := mload(0x60)

            // store public inputs
            mstore(add(p, 0x40), calldataload(0x4))
            mstore(add(p, 0x60), calldataload(0x24))
            mstore(add(p, 0x80), calldataload(0x44))
            mstore(add(p, 0xa0), calldataload(0x64))
            mstore(add(p, 0xc0), calldataload(0x84))
            mstore(add(p, 0xe0), calldataload(0xa4))
            // extend public inputs
            mstore(add(p, 0x100), zero)
            mstore(add(p, 0x120), zero)
            mstore(add(p, 0x140), zero)
            mstore(add(p, 0x160), zero)
            mstore(add(p, 0x180), zero)
            mstore(add(p, 0x1a0), zero)
            mstore(add(p, 0x1c0), zero)
            mstore(add(p, 0x1e0), zero)
            mstore(add(p, 0x200), zero)
            mstore(add(p, 0x220), zero)
            mstore(add(p, 0x240), zero)
            mstore(add(p, 0x260), zero)
            mstore(add(p, 0x280), zero)
            mstore(add(p, 0x2a0), zero)
            // public inputs hash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x280))

            // verify on quantum
            mstore(add(p, 0x20), vkHash)
            mstore(p, SIGNATURE_PIS_HASHES)
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

    function verifyOldPubInputs(
        ProtocolInclusionProof calldata protocolInclusionProof,
        uint256[6] calldata pubInputs,
        bytes32 vKeyHash,
        address quantum_verifier
    ) internal view {
        assembly {
            let p := mload(0x40)
            let zero := mload(0x60)

            // ** computer leaf value = keccak(vKeyHash || keccak(extend(pubInputs))) **
            // store pub inputs
            mstore(p, calldataload(0x1a4))
            mstore(add(p, 0x20), calldataload(0x1c4))
            mstore(add(p, 0x40), calldataload(0x1e4))
            mstore(add(p, 0x60), calldataload(0x204))
            mstore(add(p, 0x80), calldataload(0x224))
            mstore(add(p, 0xa0), calldataload(0x244))
            // extend public inputs
            mstore(add(p, 0xc0), zero)
            mstore(add(p, 0xe0), zero)
            mstore(add(p, 0x100), zero)
            mstore(add(p, 0x120), zero)
            mstore(add(p, 0x140), zero)
            mstore(add(p, 0x160), zero)
            mstore(add(p, 0x180), zero)
            mstore(add(p, 0x1a0), zero)
            mstore(add(p, 0x1c0), zero)
            mstore(add(p, 0x1e0), zero)
            mstore(add(p, 0x200), zero)
            mstore(add(p, 0x220), zero)
            mstore(add(p, 0x240), zero)
            mstore(add(p, 0x260), zero)

            // keccak(extend(pubInputs)))
            mstore(add(p, 0x20), keccak256(p, 0x280))

            // vKeyHash
            mstore(p, vKeyHash)

            // construct leaf
            mstore(add(p, 0x40), keccak256(p, 0x40)) // leaf value
            mstore(add(p, 0x60), calldataload(0x164)) // leaf next value
            mstore(add(p, 0x80), calldataload(0x184)) // leaf next idx

            // compute leafHash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x48)) //  storing leafHash at p+0x40; all earlier data at any memory can be discarded

            mstore(p, calldataload(0x4)) // load merkle-proof-position at `p`

            // computing root (at `p+0x40`) using 10 proof elms and their position
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

library ProtocolVerifier_7 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE_PIS_HASHES = 0x70e8daf7;
    uint256 constant SIGNATURE_TREE_ROOT = 0x14dc6c14;

    struct ProtocolInclusionProof {
        uint256 merkleProofPosition;
        bytes32[10] merkleProof;
        bytes32 leafNextValue;
        bytes8 leafNextIdx;
    }

    function verifyLatestPubInputs(
        uint256[7] calldata pubInputs,
        bytes32 vkHash,
        address quantum_verifier
    ) internal view {
        assembly {
            let p := mload(0x40)
            let zero := mload(0x60)

            // store public inputs
            mstore(add(p, 0x40), calldataload(0x4))
            mstore(add(p, 0x60), calldataload(0x24))
            mstore(add(p, 0x80), calldataload(0x44))
            mstore(add(p, 0xa0), calldataload(0x64))
            mstore(add(p, 0xc0), calldataload(0x84))
            mstore(add(p, 0xe0), calldataload(0xa4))
            mstore(add(p, 0x100), calldataload(0xc4))
            // extend public inputs
            mstore(add(p, 0x120), zero)
            mstore(add(p, 0x140), zero)
            mstore(add(p, 0x160), zero)
            mstore(add(p, 0x180), zero)
            mstore(add(p, 0x1a0), zero)
            mstore(add(p, 0x1c0), zero)
            mstore(add(p, 0x1e0), zero)
            mstore(add(p, 0x200), zero)
            mstore(add(p, 0x220), zero)
            mstore(add(p, 0x240), zero)
            mstore(add(p, 0x260), zero)
            mstore(add(p, 0x280), zero)
            mstore(add(p, 0x2a0), zero)
            // public inputs hash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x280))

            // verify on quantum
            mstore(add(p, 0x20), vkHash)
            mstore(p, SIGNATURE_PIS_HASHES)
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

    function verifyOldPubInputs(
        ProtocolInclusionProof calldata protocolInclusionProof,
        uint256[7] calldata pubInputs,
        bytes32 vKeyHash,
        address quantum_verifier
    ) internal view {
        assembly {
            let p := mload(0x40)
            let zero := mload(0x60)

            // ** computer leaf value = keccak(vKeyHash || keccak(extend(pubInputs))) **
            // store pub inputs
            mstore(p, calldataload(0x1a4))
            mstore(add(p, 0x20), calldataload(0x1c4))
            mstore(add(p, 0x40), calldataload(0x1e4))
            mstore(add(p, 0x60), calldataload(0x204))
            mstore(add(p, 0x80), calldataload(0x224))
            mstore(add(p, 0xa0), calldataload(0x244))
            mstore(add(p, 0xc0), calldataload(0x264))
            // extend public inputs
            mstore(add(p, 0xe0), zero)
            mstore(add(p, 0x100), zero)
            mstore(add(p, 0x120), zero)
            mstore(add(p, 0x140), zero)
            mstore(add(p, 0x160), zero)
            mstore(add(p, 0x180), zero)
            mstore(add(p, 0x1a0), zero)
            mstore(add(p, 0x1c0), zero)
            mstore(add(p, 0x1e0), zero)
            mstore(add(p, 0x200), zero)
            mstore(add(p, 0x220), zero)
            mstore(add(p, 0x240), zero)
            mstore(add(p, 0x260), zero)

            // keccak(extend(pubInputs)))
            mstore(add(p, 0x20), keccak256(p, 0x280))

            // vKeyHash
            mstore(p, vKeyHash)

            // construct leaf
            mstore(add(p, 0x40), keccak256(p, 0x40)) // leaf value
            mstore(add(p, 0x60), calldataload(0x164)) // leaf next value
            mstore(add(p, 0x80), calldataload(0x184)) // leaf next idx

            // compute leafHash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x48)) //  storing leafHash at p+0x40; all earlier data at any memory can be discarded

            mstore(p, calldataload(0x4)) // load merkle-proof-position at `p`

            // computing root (at `p+0x40`) using 10 proof elms and their position
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

library ProtocolVerifier_8 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE_PIS_HASHES = 0x70e8daf7;
    uint256 constant SIGNATURE_TREE_ROOT = 0x14dc6c14;

    struct ProtocolInclusionProof {
        uint256 merkleProofPosition;
        bytes32[10] merkleProof;
        bytes32 leafNextValue;
        bytes8 leafNextIdx;
    }

    function verifyLatestPubInputs(
        uint256[8] calldata pubInputs,
        bytes32 vkHash,
        address quantum_verifier
    ) internal view {
        assembly {
            let p := mload(0x40)
            let zero := mload(0x60)

            // store public inputs
            mstore(add(p, 0x40), calldataload(0x4))
            mstore(add(p, 0x60), calldataload(0x24))
            mstore(add(p, 0x80), calldataload(0x44))
            mstore(add(p, 0xa0), calldataload(0x64))
            mstore(add(p, 0xc0), calldataload(0x84))
            mstore(add(p, 0xe0), calldataload(0xa4))
            mstore(add(p, 0x100), calldataload(0xc4))
            mstore(add(p, 0x120), calldataload(0xe4))
            // extend public inputs
            mstore(add(p, 0x140), zero)
            mstore(add(p, 0x160), zero)
            mstore(add(p, 0x180), zero)
            mstore(add(p, 0x1a0), zero)
            mstore(add(p, 0x1c0), zero)
            mstore(add(p, 0x1e0), zero)
            mstore(add(p, 0x200), zero)
            mstore(add(p, 0x220), zero)
            mstore(add(p, 0x240), zero)
            mstore(add(p, 0x260), zero)
            mstore(add(p, 0x280), zero)
            mstore(add(p, 0x2a0), zero)
            // public inputs hash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x280))

            // verify on quantum
            mstore(add(p, 0x20), vkHash)
            mstore(p, SIGNATURE_PIS_HASHES)
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

    function verifyOldPubInputs(
        ProtocolInclusionProof calldata protocolInclusionProof,
        uint256[8] calldata pubInputs,
        bytes32 vKeyHash,
        address quantum_verifier
    ) internal view {
        assembly {
            let p := mload(0x40)
            let zero := mload(0x60)

            // ** computer leaf value = keccak(vKeyHash || keccak(extend(pubInputs))) **
            // store pub inputs
            mstore(p, calldataload(0x1a4))
            mstore(add(p, 0x20), calldataload(0x1c4))
            mstore(add(p, 0x40), calldataload(0x1e4))
            mstore(add(p, 0x60), calldataload(0x204))
            mstore(add(p, 0x80), calldataload(0x224))
            mstore(add(p, 0xa0), calldataload(0x244))
            mstore(add(p, 0xc0), calldataload(0x264))
            mstore(add(p, 0xe0), calldataload(0x284))
            // extend public inputs
            mstore(add(p, 0x100), zero)
            mstore(add(p, 0x120), zero)
            mstore(add(p, 0x140), zero)
            mstore(add(p, 0x160), zero)
            mstore(add(p, 0x180), zero)
            mstore(add(p, 0x1a0), zero)
            mstore(add(p, 0x1c0), zero)
            mstore(add(p, 0x1e0), zero)
            mstore(add(p, 0x200), zero)
            mstore(add(p, 0x220), zero)
            mstore(add(p, 0x240), zero)
            mstore(add(p, 0x260), zero)

            // keccak(extend(pubInputs)))
            mstore(add(p, 0x20), keccak256(p, 0x280))

            // vKeyHash
            mstore(p, vKeyHash)

            // construct leaf
            mstore(add(p, 0x40), keccak256(p, 0x40)) // leaf value
            mstore(add(p, 0x60), calldataload(0x164)) // leaf next value
            mstore(add(p, 0x80), calldataload(0x184)) // leaf next idx

            // compute leafHash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x48)) //  storing leafHash at p+0x40; all earlier data at any memory can be discarded

            mstore(p, calldataload(0x4)) // load merkle-proof-position at `p`

            // computing root (at `p+0x40`) using 10 proof elms and their position
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

library ProtocolVerifier_9 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE_PIS_HASHES = 0x70e8daf7;
    uint256 constant SIGNATURE_TREE_ROOT = 0x14dc6c14;

    struct ProtocolInclusionProof {
        uint256 merkleProofPosition;
        bytes32[10] merkleProof;
        bytes32 leafNextValue;
        bytes8 leafNextIdx;
    }

    function verifyLatestPubInputs(
        uint256[9] calldata pubInputs,
        bytes32 vkHash,
        address quantum_verifier
    ) internal view {
        assembly {
            let p := mload(0x40)
            let zero := mload(0x60)

            // store public inputs
            mstore(add(p, 0x40), calldataload(0x4))
            mstore(add(p, 0x60), calldataload(0x24))
            mstore(add(p, 0x80), calldataload(0x44))
            mstore(add(p, 0xa0), calldataload(0x64))
            mstore(add(p, 0xc0), calldataload(0x84))
            mstore(add(p, 0xe0), calldataload(0xa4))
            mstore(add(p, 0x100), calldataload(0xc4))
            mstore(add(p, 0x120), calldataload(0xe4))
            mstore(add(p, 0x140), calldataload(0x104))
            // extend public inputs
            mstore(add(p, 0x160), zero)
            mstore(add(p, 0x180), zero)
            mstore(add(p, 0x1a0), zero)
            mstore(add(p, 0x1c0), zero)
            mstore(add(p, 0x1e0), zero)
            mstore(add(p, 0x200), zero)
            mstore(add(p, 0x220), zero)
            mstore(add(p, 0x240), zero)
            mstore(add(p, 0x260), zero)
            mstore(add(p, 0x280), zero)
            mstore(add(p, 0x2a0), zero)
            // public inputs hash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x280))

            // verify on quantum
            mstore(add(p, 0x20), vkHash)
            mstore(p, SIGNATURE_PIS_HASHES)
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

    function verifyOldPubInputs(
        ProtocolInclusionProof calldata protocolInclusionProof,
        uint256[9] calldata pubInputs,
        bytes32 vKeyHash,
        address quantum_verifier
    ) internal view {
        assembly {
            let p := mload(0x40)
            let zero := mload(0x60)

            // ** computer leaf value = keccak(vKeyHash || keccak(extend(pubInputs))) **
            // store pub inputs
            mstore(p, calldataload(0x1a4))
            mstore(add(p, 0x20), calldataload(0x1c4))
            mstore(add(p, 0x40), calldataload(0x1e4))
            mstore(add(p, 0x60), calldataload(0x204))
            mstore(add(p, 0x80), calldataload(0x224))
            mstore(add(p, 0xa0), calldataload(0x244))
            mstore(add(p, 0xc0), calldataload(0x264))
            mstore(add(p, 0xe0), calldataload(0x284))
            mstore(add(p, 0x100), calldataload(0x2a4))
            // extend public inputs
            mstore(add(p, 0x120), zero)
            mstore(add(p, 0x140), zero)
            mstore(add(p, 0x160), zero)
            mstore(add(p, 0x180), zero)
            mstore(add(p, 0x1a0), zero)
            mstore(add(p, 0x1c0), zero)
            mstore(add(p, 0x1e0), zero)
            mstore(add(p, 0x200), zero)
            mstore(add(p, 0x220), zero)
            mstore(add(p, 0x240), zero)
            mstore(add(p, 0x260), zero)

            // keccak(extend(pubInputs)))
            mstore(add(p, 0x20), keccak256(p, 0x280))

            // vKeyHash
            mstore(p, vKeyHash)

            // construct leaf
            mstore(add(p, 0x40), keccak256(p, 0x40)) // leaf value
            mstore(add(p, 0x60), calldataload(0x164)) // leaf next value
            mstore(add(p, 0x80), calldataload(0x184)) // leaf next idx

            // compute leafHash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x48)) //  storing leafHash at p+0x40; all earlier data at any memory can be discarded

            mstore(p, calldataload(0x4)) // load merkle-proof-position at `p`

            // computing root (at `p+0x40`) using 10 proof elms and their position
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

library ProtocolVerifier_10 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE_PIS_HASHES = 0x70e8daf7;
    uint256 constant SIGNATURE_TREE_ROOT = 0x14dc6c14;

    struct ProtocolInclusionProof {
        uint256 merkleProofPosition;
        bytes32[10] merkleProof;
        bytes32 leafNextValue;
        bytes8 leafNextIdx;
    }

    function verifyLatestPubInputs(
        uint256[10] calldata pubInputs,
        bytes32 vkHash,
        address quantum_verifier
    ) internal view {
        assembly {
            let p := mload(0x40)
            let zero := mload(0x60)

            // store public inputs
            mstore(add(p, 0x40), calldataload(0x4))
            mstore(add(p, 0x60), calldataload(0x24))
            mstore(add(p, 0x80), calldataload(0x44))
            mstore(add(p, 0xa0), calldataload(0x64))
            mstore(add(p, 0xc0), calldataload(0x84))
            mstore(add(p, 0xe0), calldataload(0xa4))
            mstore(add(p, 0x100), calldataload(0xc4))
            mstore(add(p, 0x120), calldataload(0xe4))
            mstore(add(p, 0x140), calldataload(0x104))
            mstore(add(p, 0x160), calldataload(0x124))
            // extend public inputs
            mstore(add(p, 0x180), zero)
            mstore(add(p, 0x1a0), zero)
            mstore(add(p, 0x1c0), zero)
            mstore(add(p, 0x1e0), zero)
            mstore(add(p, 0x200), zero)
            mstore(add(p, 0x220), zero)
            mstore(add(p, 0x240), zero)
            mstore(add(p, 0x260), zero)
            mstore(add(p, 0x280), zero)
            mstore(add(p, 0x2a0), zero)
            // public inputs hash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x280))

            // verify on quantum
            mstore(add(p, 0x20), vkHash)
            mstore(p, SIGNATURE_PIS_HASHES)
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

    function verifyOldPubInputs(
        ProtocolInclusionProof calldata protocolInclusionProof,
        uint256[10] calldata pubInputs,
        bytes32 vKeyHash,
        address quantum_verifier
    ) internal view {
        assembly {
            let p := mload(0x40)
            let zero := mload(0x60)

            // ** computer leaf value = keccak(vKeyHash || keccak(extend(pubInputs))) **
            // store pub inputs
            mstore(p, calldataload(0x1a4))
            mstore(add(p, 0x20), calldataload(0x1c4))
            mstore(add(p, 0x40), calldataload(0x1e4))
            mstore(add(p, 0x60), calldataload(0x204))
            mstore(add(p, 0x80), calldataload(0x224))
            mstore(add(p, 0xa0), calldataload(0x244))
            mstore(add(p, 0xc0), calldataload(0x264))
            mstore(add(p, 0xe0), calldataload(0x284))
            mstore(add(p, 0x100), calldataload(0x2a4))
            mstore(add(p, 0x120), calldataload(0x2c4))
            // extend public inputs
            mstore(add(p, 0x140), zero)
            mstore(add(p, 0x160), zero)
            mstore(add(p, 0x180), zero)
            mstore(add(p, 0x1a0), zero)
            mstore(add(p, 0x1c0), zero)
            mstore(add(p, 0x1e0), zero)
            mstore(add(p, 0x200), zero)
            mstore(add(p, 0x220), zero)
            mstore(add(p, 0x240), zero)
            mstore(add(p, 0x260), zero)

            // keccak(extend(pubInputs)))
            mstore(add(p, 0x20), keccak256(p, 0x280))

            // vKeyHash
            mstore(p, vKeyHash)

            // construct leaf
            mstore(add(p, 0x40), keccak256(p, 0x40)) // leaf value
            mstore(add(p, 0x60), calldataload(0x164)) // leaf next value
            mstore(add(p, 0x80), calldataload(0x184)) // leaf next idx

            // compute leafHash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x48)) //  storing leafHash at p+0x40; all earlier data at any memory can be discarded

            mstore(p, calldataload(0x4)) // load merkle-proof-position at `p`

            // computing root (at `p+0x40`) using 10 proof elms and their position
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

library ProtocolVerifier_11 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE_PIS_HASHES = 0x70e8daf7;
    uint256 constant SIGNATURE_TREE_ROOT = 0x14dc6c14;

    struct ProtocolInclusionProof {
        uint256 merkleProofPosition;
        bytes32[10] merkleProof;
        bytes32 leafNextValue;
        bytes8 leafNextIdx;
    }

    function verifyLatestPubInputs(
        uint256[11] calldata pubInputs,
        bytes32 vkHash,
        address quantum_verifier
    ) internal view {
        assembly {
            let p := mload(0x40)
            let zero := mload(0x60)

            // store public inputs
            mstore(add(p, 0x40), calldataload(0x4))
            mstore(add(p, 0x60), calldataload(0x24))
            mstore(add(p, 0x80), calldataload(0x44))
            mstore(add(p, 0xa0), calldataload(0x64))
            mstore(add(p, 0xc0), calldataload(0x84))
            mstore(add(p, 0xe0), calldataload(0xa4))
            mstore(add(p, 0x100), calldataload(0xc4))
            mstore(add(p, 0x120), calldataload(0xe4))
            mstore(add(p, 0x140), calldataload(0x104))
            mstore(add(p, 0x160), calldataload(0x124))
            mstore(add(p, 0x180), calldataload(0x144))
            // extend public inputs
            mstore(add(p, 0x1a0), zero)
            mstore(add(p, 0x1c0), zero)
            mstore(add(p, 0x1e0), zero)
            mstore(add(p, 0x200), zero)
            mstore(add(p, 0x220), zero)
            mstore(add(p, 0x240), zero)
            mstore(add(p, 0x260), zero)
            mstore(add(p, 0x280), zero)
            mstore(add(p, 0x2a0), zero)
            // public inputs hash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x280))

            // verify on quantum
            mstore(add(p, 0x20), vkHash)
            mstore(p, SIGNATURE_PIS_HASHES)
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

    function verifyOldPubInputs(
        ProtocolInclusionProof calldata protocolInclusionProof,
        uint256[11] calldata pubInputs,
        bytes32 vKeyHash,
        address quantum_verifier
    ) internal view {
        assembly {
            let p := mload(0x40)
            let zero := mload(0x60)

            // ** computer leaf value = keccak(vKeyHash || keccak(extend(pubInputs))) **
            // store pub inputs
            mstore(p, calldataload(0x1a4))
            mstore(add(p, 0x20), calldataload(0x1c4))
            mstore(add(p, 0x40), calldataload(0x1e4))
            mstore(add(p, 0x60), calldataload(0x204))
            mstore(add(p, 0x80), calldataload(0x224))
            mstore(add(p, 0xa0), calldataload(0x244))
            mstore(add(p, 0xc0), calldataload(0x264))
            mstore(add(p, 0xe0), calldataload(0x284))
            mstore(add(p, 0x100), calldataload(0x2a4))
            mstore(add(p, 0x120), calldataload(0x2c4))
            mstore(add(p, 0x140), calldataload(0x2e4))
            // extend public inputs
            mstore(add(p, 0x160), zero)
            mstore(add(p, 0x180), zero)
            mstore(add(p, 0x1a0), zero)
            mstore(add(p, 0x1c0), zero)
            mstore(add(p, 0x1e0), zero)
            mstore(add(p, 0x200), zero)
            mstore(add(p, 0x220), zero)
            mstore(add(p, 0x240), zero)
            mstore(add(p, 0x260), zero)

            // keccak(extend(pubInputs)))
            mstore(add(p, 0x20), keccak256(p, 0x280))

            // vKeyHash
            mstore(p, vKeyHash)

            // construct leaf
            mstore(add(p, 0x40), keccak256(p, 0x40)) // leaf value
            mstore(add(p, 0x60), calldataload(0x164)) // leaf next value
            mstore(add(p, 0x80), calldataload(0x184)) // leaf next idx

            // compute leafHash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x48)) //  storing leafHash at p+0x40; all earlier data at any memory can be discarded

            mstore(p, calldataload(0x4)) // load merkle-proof-position at `p`

            // computing root (at `p+0x40`) using 10 proof elms and their position
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

library ProtocolVerifier_12 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE_PIS_HASHES = 0x70e8daf7;
    uint256 constant SIGNATURE_TREE_ROOT = 0x14dc6c14;

    struct ProtocolInclusionProof {
        uint256 merkleProofPosition;
        bytes32[10] merkleProof;
        bytes32 leafNextValue;
        bytes8 leafNextIdx;
    }

    function verifyLatestPubInputs(
        uint256[12] calldata pubInputs,
        bytes32 vkHash,
        address quantum_verifier
    ) internal view {
        assembly {
            let p := mload(0x40)
            let zero := mload(0x60)

            // store public inputs
            mstore(add(p, 0x40), calldataload(0x4))
            mstore(add(p, 0x60), calldataload(0x24))
            mstore(add(p, 0x80), calldataload(0x44))
            mstore(add(p, 0xa0), calldataload(0x64))
            mstore(add(p, 0xc0), calldataload(0x84))
            mstore(add(p, 0xe0), calldataload(0xa4))
            mstore(add(p, 0x100), calldataload(0xc4))
            mstore(add(p, 0x120), calldataload(0xe4))
            mstore(add(p, 0x140), calldataload(0x104))
            mstore(add(p, 0x160), calldataload(0x124))
            mstore(add(p, 0x180), calldataload(0x144))
            mstore(add(p, 0x1a0), calldataload(0x164))
            // extend public inputs
            mstore(add(p, 0x1c0), zero)
            mstore(add(p, 0x1e0), zero)
            mstore(add(p, 0x200), zero)
            mstore(add(p, 0x220), zero)
            mstore(add(p, 0x240), zero)
            mstore(add(p, 0x260), zero)
            mstore(add(p, 0x280), zero)
            mstore(add(p, 0x2a0), zero)
            // public inputs hash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x280))

            // verify on quantum
            mstore(add(p, 0x20), vkHash)
            mstore(p, SIGNATURE_PIS_HASHES)
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

    function verifyOldPubInputs(
        ProtocolInclusionProof calldata protocolInclusionProof,
        uint256[12] calldata pubInputs,
        bytes32 vKeyHash,
        address quantum_verifier
    ) internal view {
        assembly {
            let p := mload(0x40)
            let zero := mload(0x60)

            // ** computer leaf value = keccak(vKeyHash || keccak(extend(pubInputs))) **
            // store pub inputs
            mstore(p, calldataload(0x1a4))
            mstore(add(p, 0x20), calldataload(0x1c4))
            mstore(add(p, 0x40), calldataload(0x1e4))
            mstore(add(p, 0x60), calldataload(0x204))
            mstore(add(p, 0x80), calldataload(0x224))
            mstore(add(p, 0xa0), calldataload(0x244))
            mstore(add(p, 0xc0), calldataload(0x264))
            mstore(add(p, 0xe0), calldataload(0x284))
            mstore(add(p, 0x100), calldataload(0x2a4))
            mstore(add(p, 0x120), calldataload(0x2c4))
            mstore(add(p, 0x140), calldataload(0x2e4))
            mstore(add(p, 0x160), calldataload(0x304))
            // extend public inputs
            mstore(add(p, 0x180), zero)
            mstore(add(p, 0x1a0), zero)
            mstore(add(p, 0x1c0), zero)
            mstore(add(p, 0x1e0), zero)
            mstore(add(p, 0x200), zero)
            mstore(add(p, 0x220), zero)
            mstore(add(p, 0x240), zero)
            mstore(add(p, 0x260), zero)

            // keccak(extend(pubInputs)))
            mstore(add(p, 0x20), keccak256(p, 0x280))

            // vKeyHash
            mstore(p, vKeyHash)

            // construct leaf
            mstore(add(p, 0x40), keccak256(p, 0x40)) // leaf value
            mstore(add(p, 0x60), calldataload(0x164)) // leaf next value
            mstore(add(p, 0x80), calldataload(0x184)) // leaf next idx

            // compute leafHash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x48)) //  storing leafHash at p+0x40; all earlier data at any memory can be discarded

            mstore(p, calldataload(0x4)) // load merkle-proof-position at `p`

            // computing root (at `p+0x40`) using 10 proof elms and their position
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

library ProtocolVerifier_13 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE_PIS_HASHES = 0x70e8daf7;
    uint256 constant SIGNATURE_TREE_ROOT = 0x14dc6c14;

    struct ProtocolInclusionProof {
        uint256 merkleProofPosition;
        bytes32[10] merkleProof;
        bytes32 leafNextValue;
        bytes8 leafNextIdx;
    }

    function verifyLatestPubInputs(
        uint256[13] calldata pubInputs,
        bytes32 vkHash,
        address quantum_verifier
    ) internal view {
        assembly {
            let p := mload(0x40)
            let zero := mload(0x60)

            // store public inputs
            mstore(add(p, 0x40), calldataload(0x4))
            mstore(add(p, 0x60), calldataload(0x24))
            mstore(add(p, 0x80), calldataload(0x44))
            mstore(add(p, 0xa0), calldataload(0x64))
            mstore(add(p, 0xc0), calldataload(0x84))
            mstore(add(p, 0xe0), calldataload(0xa4))
            mstore(add(p, 0x100), calldataload(0xc4))
            mstore(add(p, 0x120), calldataload(0xe4))
            mstore(add(p, 0x140), calldataload(0x104))
            mstore(add(p, 0x160), calldataload(0x124))
            mstore(add(p, 0x180), calldataload(0x144))
            mstore(add(p, 0x1a0), calldataload(0x164))
            mstore(add(p, 0x1c0), calldataload(0x184))
            // extend public inputs
            mstore(add(p, 0x1e0), zero)
            mstore(add(p, 0x200), zero)
            mstore(add(p, 0x220), zero)
            mstore(add(p, 0x240), zero)
            mstore(add(p, 0x260), zero)
            mstore(add(p, 0x280), zero)
            mstore(add(p, 0x2a0), zero)
            // public inputs hash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x280))

            // verify on quantum
            mstore(add(p, 0x20), vkHash)
            mstore(p, SIGNATURE_PIS_HASHES)
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

    function verifyOldPubInputs(
        ProtocolInclusionProof calldata protocolInclusionProof,
        uint256[13] calldata pubInputs,
        bytes32 vKeyHash,
        address quantum_verifier
    ) internal view {
        assembly {
            let p := mload(0x40)
            let zero := mload(0x60)

            // ** computer leaf value = keccak(vKeyHash || keccak(extend(pubInputs))) **
            // store pub inputs
            mstore(p, calldataload(0x1a4))
            mstore(add(p, 0x20), calldataload(0x1c4))
            mstore(add(p, 0x40), calldataload(0x1e4))
            mstore(add(p, 0x60), calldataload(0x204))
            mstore(add(p, 0x80), calldataload(0x224))
            mstore(add(p, 0xa0), calldataload(0x244))
            mstore(add(p, 0xc0), calldataload(0x264))
            mstore(add(p, 0xe0), calldataload(0x284))
            mstore(add(p, 0x100), calldataload(0x2a4))
            mstore(add(p, 0x120), calldataload(0x2c4))
            mstore(add(p, 0x140), calldataload(0x2e4))
            mstore(add(p, 0x160), calldataload(0x304))
            mstore(add(p, 0x180), calldataload(0x324))
            // extend public inputs
            mstore(add(p, 0x1a0), zero)
            mstore(add(p, 0x1c0), zero)
            mstore(add(p, 0x1e0), zero)
            mstore(add(p, 0x200), zero)
            mstore(add(p, 0x220), zero)
            mstore(add(p, 0x240), zero)
            mstore(add(p, 0x260), zero)

            // keccak(extend(pubInputs)))
            mstore(add(p, 0x20), keccak256(p, 0x280))

            // vKeyHash
            mstore(p, vKeyHash)

            // construct leaf
            mstore(add(p, 0x40), keccak256(p, 0x40)) // leaf value
            mstore(add(p, 0x60), calldataload(0x164)) // leaf next value
            mstore(add(p, 0x80), calldataload(0x184)) // leaf next idx

            // compute leafHash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x48)) //  storing leafHash at p+0x40; all earlier data at any memory can be discarded

            mstore(p, calldataload(0x4)) // load merkle-proof-position at `p`

            // computing root (at `p+0x40`) using 10 proof elms and their position
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

library ProtocolVerifier_14 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE_PIS_HASHES = 0x70e8daf7;
    uint256 constant SIGNATURE_TREE_ROOT = 0x14dc6c14;

    struct ProtocolInclusionProof {
        uint256 merkleProofPosition;
        bytes32[10] merkleProof;
        bytes32 leafNextValue;
        bytes8 leafNextIdx;
    }

    function verifyLatestPubInputs(
        uint256[14] calldata pubInputs,
        bytes32 vkHash,
        address quantum_verifier
    ) internal view {
        assembly {
            let p := mload(0x40)
            let zero := mload(0x60)

            // store public inputs
            mstore(add(p, 0x40), calldataload(0x4))
            mstore(add(p, 0x60), calldataload(0x24))
            mstore(add(p, 0x80), calldataload(0x44))
            mstore(add(p, 0xa0), calldataload(0x64))
            mstore(add(p, 0xc0), calldataload(0x84))
            mstore(add(p, 0xe0), calldataload(0xa4))
            mstore(add(p, 0x100), calldataload(0xc4))
            mstore(add(p, 0x120), calldataload(0xe4))
            mstore(add(p, 0x140), calldataload(0x104))
            mstore(add(p, 0x160), calldataload(0x124))
            mstore(add(p, 0x180), calldataload(0x144))
            mstore(add(p, 0x1a0), calldataload(0x164))
            mstore(add(p, 0x1c0), calldataload(0x184))
            mstore(add(p, 0x1e0), calldataload(0x1a4))
            // extend public inputs
            mstore(add(p, 0x200), zero)
            mstore(add(p, 0x220), zero)
            mstore(add(p, 0x240), zero)
            mstore(add(p, 0x260), zero)
            mstore(add(p, 0x280), zero)
            mstore(add(p, 0x2a0), zero)
            // public inputs hash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x280))

            // verify on quantum
            mstore(add(p, 0x20), vkHash)
            mstore(p, SIGNATURE_PIS_HASHES)
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

    function verifyOldPubInputs(
        ProtocolInclusionProof calldata protocolInclusionProof,
        uint256[14] calldata pubInputs,
        bytes32 vKeyHash,
        address quantum_verifier
    ) internal view {
        assembly {
            let p := mload(0x40)
            let zero := mload(0x60)

            // ** computer leaf value = keccak(vKeyHash || keccak(extend(pubInputs))) **
            // store pub inputs
            mstore(p, calldataload(0x1a4))
            mstore(add(p, 0x20), calldataload(0x1c4))
            mstore(add(p, 0x40), calldataload(0x1e4))
            mstore(add(p, 0x60), calldataload(0x204))
            mstore(add(p, 0x80), calldataload(0x224))
            mstore(add(p, 0xa0), calldataload(0x244))
            mstore(add(p, 0xc0), calldataload(0x264))
            mstore(add(p, 0xe0), calldataload(0x284))
            mstore(add(p, 0x100), calldataload(0x2a4))
            mstore(add(p, 0x120), calldataload(0x2c4))
            mstore(add(p, 0x140), calldataload(0x2e4))
            mstore(add(p, 0x160), calldataload(0x304))
            mstore(add(p, 0x180), calldataload(0x324))
            mstore(add(p, 0x1a0), calldataload(0x344))
            // extend public inputs
            mstore(add(p, 0x1c0), zero)
            mstore(add(p, 0x1e0), zero)
            mstore(add(p, 0x200), zero)
            mstore(add(p, 0x220), zero)
            mstore(add(p, 0x240), zero)
            mstore(add(p, 0x260), zero)

            // keccak(extend(pubInputs)))
            mstore(add(p, 0x20), keccak256(p, 0x280))

            // vKeyHash
            mstore(p, vKeyHash)

            // construct leaf
            mstore(add(p, 0x40), keccak256(p, 0x40)) // leaf value
            mstore(add(p, 0x60), calldataload(0x164)) // leaf next value
            mstore(add(p, 0x80), calldataload(0x184)) // leaf next idx

            // compute leafHash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x48)) //  storing leafHash at p+0x40; all earlier data at any memory can be discarded

            mstore(p, calldataload(0x4)) // load merkle-proof-position at `p`

            // computing root (at `p+0x40`) using 10 proof elms and their position
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

library ProtocolVerifier_15 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE_PIS_HASHES = 0x70e8daf7;
    uint256 constant SIGNATURE_TREE_ROOT = 0x14dc6c14;

    struct ProtocolInclusionProof {
        uint256 merkleProofPosition;
        bytes32[10] merkleProof;
        bytes32 leafNextValue;
        bytes8 leafNextIdx;
    }

    function verifyLatestPubInputs(
        uint256[15] calldata pubInputs,
        bytes32 vkHash,
        address quantum_verifier
    ) internal view {
        assembly {
            let p := mload(0x40)
            let zero := mload(0x60)

            // store public inputs
            mstore(add(p, 0x40), calldataload(0x4))
            mstore(add(p, 0x60), calldataload(0x24))
            mstore(add(p, 0x80), calldataload(0x44))
            mstore(add(p, 0xa0), calldataload(0x64))
            mstore(add(p, 0xc0), calldataload(0x84))
            mstore(add(p, 0xe0), calldataload(0xa4))
            mstore(add(p, 0x100), calldataload(0xc4))
            mstore(add(p, 0x120), calldataload(0xe4))
            mstore(add(p, 0x140), calldataload(0x104))
            mstore(add(p, 0x160), calldataload(0x124))
            mstore(add(p, 0x180), calldataload(0x144))
            mstore(add(p, 0x1a0), calldataload(0x164))
            mstore(add(p, 0x1c0), calldataload(0x184))
            mstore(add(p, 0x1e0), calldataload(0x1a4))
            mstore(add(p, 0x200), calldataload(0x1c4))
            // extend public inputs
            mstore(add(p, 0x220), zero)
            mstore(add(p, 0x240), zero)
            mstore(add(p, 0x260), zero)
            mstore(add(p, 0x280), zero)
            mstore(add(p, 0x2a0), zero)
            // public inputs hash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x280))

            // verify on quantum
            mstore(add(p, 0x20), vkHash)
            mstore(p, SIGNATURE_PIS_HASHES)
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

    function verifyOldPubInputs(
        ProtocolInclusionProof calldata protocolInclusionProof,
        uint256[15] calldata pubInputs,
        bytes32 vKeyHash,
        address quantum_verifier
    ) internal view {
        assembly {
            let p := mload(0x40)
            let zero := mload(0x60)

            // ** computer leaf value = keccak(vKeyHash || keccak(extend(pubInputs))) **
            // store pub inputs
            mstore(p, calldataload(0x1a4))
            mstore(add(p, 0x20), calldataload(0x1c4))
            mstore(add(p, 0x40), calldataload(0x1e4))
            mstore(add(p, 0x60), calldataload(0x204))
            mstore(add(p, 0x80), calldataload(0x224))
            mstore(add(p, 0xa0), calldataload(0x244))
            mstore(add(p, 0xc0), calldataload(0x264))
            mstore(add(p, 0xe0), calldataload(0x284))
            mstore(add(p, 0x100), calldataload(0x2a4))
            mstore(add(p, 0x120), calldataload(0x2c4))
            mstore(add(p, 0x140), calldataload(0x2e4))
            mstore(add(p, 0x160), calldataload(0x304))
            mstore(add(p, 0x180), calldataload(0x324))
            mstore(add(p, 0x1a0), calldataload(0x344))
            mstore(add(p, 0x1c0), calldataload(0x364))
            // extend public inputs
            mstore(add(p, 0x1e0), zero)
            mstore(add(p, 0x200), zero)
            mstore(add(p, 0x220), zero)
            mstore(add(p, 0x240), zero)
            mstore(add(p, 0x260), zero)

            // keccak(extend(pubInputs)))
            mstore(add(p, 0x20), keccak256(p, 0x280))

            // vKeyHash
            mstore(p, vKeyHash)

            // construct leaf
            mstore(add(p, 0x40), keccak256(p, 0x40)) // leaf value
            mstore(add(p, 0x60), calldataload(0x164)) // leaf next value
            mstore(add(p, 0x80), calldataload(0x184)) // leaf next idx

            // compute leafHash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x48)) //  storing leafHash at p+0x40; all earlier data at any memory can be discarded

            mstore(p, calldataload(0x4)) // load merkle-proof-position at `p`

            // computing root (at `p+0x40`) using 10 proof elms and their position
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
