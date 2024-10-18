// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "hardhat/console.sol";

library ProtocolVerifier_1 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE_PUB_INPUTS_HASH = 0x4015817b;
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
            // public inputs hash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x20))

            // verify on quantum
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

            // keccak(extend(pubInputs)))
            mstore(add(p, 0x20), keccak256(p, 0x20))

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
    uint256 constant SIGNATURE_PUB_INPUTS_HASH = 0x4015817b;
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
            // public inputs hash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))

            // verify on quantum
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

            // keccak(extend(pubInputs)))
            mstore(add(p, 0x20), keccak256(p, 0x40))

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
    uint256 constant SIGNATURE_PUB_INPUTS_HASH = 0x4015817b;
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
            // public inputs hash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x60))

            // verify on quantum
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

            // keccak(extend(pubInputs)))
            mstore(add(p, 0x20), keccak256(p, 0x60))

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
    uint256 constant SIGNATURE_PUB_INPUTS_HASH = 0x4015817b;
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
            // public inputs hash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x80))

            // verify on quantum
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

            // keccak(extend(pubInputs)))
            mstore(add(p, 0x20), keccak256(p, 0x80))

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
    uint256 constant SIGNATURE_PUB_INPUTS_HASH = 0x4015817b;
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
            // public inputs hash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0xa0))

            // verify on quantum
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

            // keccak(extend(pubInputs)))
            mstore(add(p, 0x20), keccak256(p, 0xa0))

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
    uint256 constant SIGNATURE_PUB_INPUTS_HASH = 0x4015817b;
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
            // public inputs hash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0xc0))

            // verify on quantum
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

            // keccak(extend(pubInputs)))
            mstore(add(p, 0x20), keccak256(p, 0xc0))

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
    uint256 constant SIGNATURE_PUB_INPUTS_HASH = 0x4015817b;
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
            // public inputs hash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0xe0))

            // verify on quantum
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

            // keccak(extend(pubInputs)))
            mstore(add(p, 0x20), keccak256(p, 0xe0))

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
    uint256 constant SIGNATURE_PUB_INPUTS_HASH = 0x4015817b;
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
            // public inputs hash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x100))

            // verify on quantum
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

            // keccak(extend(pubInputs)))
            mstore(add(p, 0x20), keccak256(p, 0x100))

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
    uint256 constant SIGNATURE_PUB_INPUTS_HASH = 0x4015817b;
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
            // public inputs hash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x120))

            // verify on quantum
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

            // keccak(extend(pubInputs)))
            mstore(add(p, 0x20), keccak256(p, 0x120))

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
    uint256 constant SIGNATURE_PUB_INPUTS_HASH = 0x4015817b;
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
            // public inputs hash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x140))

            // verify on quantum
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

            // keccak(extend(pubInputs)))
            mstore(add(p, 0x20), keccak256(p, 0x140))

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
    uint256 constant SIGNATURE_PUB_INPUTS_HASH = 0x4015817b;
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
            // public inputs hash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x160))

            // verify on quantum
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

            // keccak(extend(pubInputs)))
            mstore(add(p, 0x20), keccak256(p, 0x160))

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
    uint256 constant SIGNATURE_PUB_INPUTS_HASH = 0x4015817b;
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
            // public inputs hash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x180))

            // verify on quantum
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

            // keccak(extend(pubInputs)))
            mstore(add(p, 0x20), keccak256(p, 0x180))

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
    uint256 constant SIGNATURE_PUB_INPUTS_HASH = 0x4015817b;
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
            // public inputs hash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x1a0))

            // verify on quantum
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

            // keccak(extend(pubInputs)))
            mstore(add(p, 0x20), keccak256(p, 0x1a0))

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
    // uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE_TREE_ROOT_VERIFIED = 0x1ed591e9;

    struct ProtocolInclusionProof {
        uint256 merkleProofPosition;
        bytes32[10] merkleProof;
    }

    function verifyPubInputs_14(
        uint256[14] calldata pubInputs,
        bytes32 combinedVKeyHash,
        address quantum_verifier,
        uint256 merkleProofPosition,
        bytes32[] calldata merkleProof
    ) internal view {
        bytes32 out;
        assembly {
            let p := mload(0x40)
            // let zero := mload(0x60)

            // ** compute leaf = keccak(combinedVKeyHash || keccak(pubInputs)) **
            // store pub inputs
            mstore(p, calldataload(0x40))
            mstore(add(p, 0x20), calldataload(0x60))
            mstore(add(p, 0x40), calldataload(0x80))
            mstore(add(p, 0x60), calldataload(0xa0))
            mstore(add(p, 0x80), calldataload(0xc0))
            mstore(add(p, 0xa0), calldataload(0xe0))
            mstore(add(p, 0xc0), calldataload(0x100))
            mstore(add(p, 0xe0), calldataload(0x120))
            mstore(add(p, 0x100), calldataload(0x140))
            mstore(add(p, 0x120), calldataload(0x160))
            mstore(add(p, 0x140), calldataload(0x180))
            mstore(add(p, 0x160), calldataload(0x1a0))
            mstore(add(p, 0x180), calldataload(0x1c0))
            mstore(add(p, 0x1a0), calldataload(0x1e0))

            // keccak(pubInputs))
            mstore(add(p, 0x20), keccak256(p, 0x1c0))

            // combinedVKeyHash
            mstore(p, combinedVKeyHash)

            // storing leaf at p+0x40; all earlier data at any memory can be discarded
            mstore(add(p, 0x40), keccak256(p, 0x40))

            // out := mload()

            // // compute leafHash
            // mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x48)) //  storing leafHash at p+0x40; all earlier data at any memory can be discarded

            // mstore(p, calldataload(0x4)) // load merkle-proof-position at `p`

            // // computing root (at `p+0x40`) using 10 proof elms and their position
            // switch and(mload(p), ONE)
            // case 1 {
            //     mstore(add(p, 0x60), calldataload(0x24))
            //     mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
            // }
            // default {
            //     mstore(add(p, 0x20), calldataload(0x24))
            //     mstore(add(p, 0x40), keccak256(add(p, 0x20), 0x40))
            // }
            // mstore(p, shr(1, mload(p))) // update next position

            // switch and(mload(p), ONE)
            // case 1 {
            //     mstore(add(p, 0x60), calldataload(0x44))
            //     mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
            // }
            // default {
            //     mstore(add(p, 0x20), calldataload(0x44))
            //     mstore(add(p, 0x40), keccak256(add(p, 0x20), 0x40))
            // }
            // mstore(p, shr(1, mload(p))) // update next position

            // switch and(mload(p), ONE)
            // case 1 {
            //     mstore(add(p, 0x60), calldataload(0x64))
            //     mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
            // }
            // default {
            //     mstore(add(p, 0x20), calldataload(0x64))
            //     mstore(add(p, 0x40), keccak256(add(p, 0x20), 0x40))
            // }
            // mstore(p, shr(1, mload(p))) // update next position

            // switch and(mload(p), ONE)
            // case 1 {
            //     mstore(add(p, 0x60), calldataload(0x84))
            //     mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
            // }
            // default {
            //     mstore(add(p, 0x20), calldataload(0x84))
            //     mstore(add(p, 0x40), keccak256(add(p, 0x20), 0x40))
            // }
            // mstore(p, shr(1, mload(p))) // update next position

            // switch and(mload(p), ONE)
            // case 1 {
            //     mstore(add(p, 0x60), calldataload(0xa4))
            //     mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
            // }
            // default {
            //     mstore(add(p, 0x20), calldataload(0xa4))
            //     mstore(add(p, 0x40), keccak256(add(p, 0x20), 0x40))
            // }
            // mstore(p, shr(1, mload(p))) // update next position

            // switch and(mload(p), ONE)
            // case 1 {
            //     mstore(add(p, 0x60), calldataload(0xc4))
            //     mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
            // }
            // default {
            //     mstore(add(p, 0x20), calldataload(0xc4))
            //     mstore(add(p, 0x40), keccak256(add(p, 0x20), 0x40))
            // }
            // mstore(p, shr(1, mload(p))) // update next position

            // switch and(mload(p), ONE)
            // case 1 {
            //     mstore(add(p, 0x60), calldataload(0xe4))
            //     mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
            // }
            // default {
            //     mstore(add(p, 0x20), calldataload(0xe4))
            //     mstore(add(p, 0x40), keccak256(add(p, 0x20), 0x40))
            // }
            // mstore(p, shr(1, mload(p))) // update next position

            // switch and(mload(p), ONE)
            // case 1 {
            //     mstore(add(p, 0x60), calldataload(0x104))
            //     mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
            // }
            // default {
            //     mstore(add(p, 0x20), calldataload(0x104))
            //     mstore(add(p, 0x40), keccak256(add(p, 0x20), 0x40))
            // }
            // mstore(p, shr(1, mload(p))) // update next position

            // switch and(mload(p), ONE)
            // case 1 {
            //     mstore(add(p, 0x60), calldataload(0x124))
            //     mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
            // }
            // default {
            //     mstore(add(p, 0x20), calldataload(0x124))
            //     mstore(add(p, 0x40), keccak256(add(p, 0x20), 0x40))
            // }
            // mstore(p, shr(1, mload(p))) // update next position

            // switch and(mload(p), ONE)
            // case 1 {
            //     mstore(add(p, 0x60), calldataload(0x144))
            //     mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
            // }
            // default {
            //     mstore(add(p, 0x20), calldataload(0x144))
            //     mstore(add(p, 0x40), keccak256(add(p, 0x20), 0x40))
            // }

            // mstore(p, SIGNATURE_TREE_ROOT)
            // let ok := staticcall(
            //     gas(),
            //     quantum_verifier,
            //     add(p, 0x1c),
            //     0x4,
            //     add(p, 0x20),
            //     0x20
            // )
            // if iszero(eq(mload(add(p, 0x20)), mload(add(p, 0x40)))) {
            //     revert(0, 0)
            // }
        }

        console.log("out");
        console.logBytes32(out);
    }
}

library ProtocolVerifier_15 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE_PUB_INPUTS_HASH = 0x4015817b;
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
            // public inputs hash
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x1e0))

            // verify on quantum
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

            // keccak(extend(pubInputs)))
            mstore(add(p, 0x20), keccak256(p, 0x1e0))

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
