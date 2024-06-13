// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

library ProtocolVerifier_0 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE = 0xc19d93fb;

    struct ProtocolInclusionProof {
        bytes32 protocolVKeyHash;
        bytes32 reductionVKeyHash;
        uint256 merkleProofPosition;
        bytes32[10] merkleProof;
        bytes32 leafNextValue;
        bytes8 leafNextIdx;
    }

    function verifyPubInputs(
        ProtocolInclusionProof calldata protocolInclusionProof,
        bytes32 vKeyHash,
        address quantum_verifier
    ) internal {
        assembly {
            let p := mload(0x40)

            // reduced pub inputs = compute keccak(protocolVKeyHash || pubInputs...)
            mstore(p, calldataload(0x4))
            mstore(add(p, 0x60), keccak256(p, 0x20))

            // pad reduced pub inputs
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

            mstore(p, calldataload(0x44)) // load merkle-proof-position at `p`

            // computing root (at `p+0x40`) using 10 proof elms and their position
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

library ProtocolVerifier_1 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE = 0xc19d93fb;

    struct ProtocolInclusionProof {
        bytes32 protocolVKeyHash;
        bytes32 reductionVKeyHash;
        uint256 merkleProofPosition;
        bytes32[10] merkleProof;
        bytes32 leafNextValue;
        bytes8 leafNextIdx;
        bytes32[1] pubInputs;
    }

    function verifyPubInputs(
        ProtocolInclusionProof calldata protocolInclusionProof,
        bytes32 vKeyHash,
        address quantum_verifier
    ) internal {
        assembly {
            let p := mload(0x40)

            // reduced pub inputs = compute keccak(protocolVKeyHash || pubInputs...)
            mstore(p, calldataload(0x4))
            mstore(add(p, 0x20), calldataload(0x1e4))
            mstore(add(p, 0x60), keccak256(p, 0x40))

            // pad reduced pub inputs
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

            mstore(p, calldataload(0x44)) // load merkle-proof-position at `p`

            // computing root (at `p+0x40`) using 10 proof elms and their position
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

library ProtocolVerifier_2 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE = 0xc19d93fb;

    struct ProtocolInclusionProof {
        bytes32 protocolVKeyHash;
        bytes32 reductionVKeyHash;
        uint256 merkleProofPosition;
        bytes32[10] merkleProof;
        bytes32 leafNextValue;
        bytes8 leafNextIdx;
        bytes32[2] pubInputs;
    }

    function verifyPubInputs(
        ProtocolInclusionProof calldata protocolInclusionProof,
        bytes32 vKeyHash,
        address quantum_verifier
    ) internal {
        assembly {
            let p := mload(0x40)

            // reduced pub inputs = compute keccak(protocolVKeyHash || pubInputs...)
            mstore(p, calldataload(0x4))
            mstore(add(p, 0x20), calldataload(0x1e4))
            mstore(add(p, 0x40), calldataload(0x204))
            mstore(add(p, 0x60), keccak256(p, 0x60))

            // pad reduced pub inputs
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

            mstore(p, calldataload(0x44)) // load merkle-proof-position at `p`

            // computing root (at `p+0x40`) using 10 proof elms and their position
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

library ProtocolVerifier_3 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE = 0xc19d93fb;

    struct ProtocolInclusionProof {
        bytes32 protocolVKeyHash;
        bytes32 reductionVKeyHash;
        uint256 merkleProofPosition;
        bytes32[10] merkleProof;
        bytes32 leafNextValue;
        bytes8 leafNextIdx;
        bytes32[3] pubInputs;
    }

    function verifyPubInputs(
        ProtocolInclusionProof calldata protocolInclusionProof,
        bytes32 vKeyHash,
        address quantum_verifier
    ) internal {
        assembly {
            let p := mload(0x40)

            // reduced pub inputs = compute keccak(protocolVKeyHash || pubInputs...)
            mstore(p, calldataload(0x4))
            mstore(add(p, 0x20), calldataload(0x1e4))
            mstore(add(p, 0x40), calldataload(0x204))
            mstore(add(p, 0x60), calldataload(0x224))
            mstore(add(p, 0x60), keccak256(p, 0x80))

            // pad reduced pub inputs
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

            mstore(p, calldataload(0x44)) // load merkle-proof-position at `p`

            // computing root (at `p+0x40`) using 10 proof elms and their position
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

library ProtocolVerifier_4 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE = 0xc19d93fb;

    struct ProtocolInclusionProof {
        bytes32 protocolVKeyHash;
        bytes32 reductionVKeyHash;
        uint256 merkleProofPosition;
        bytes32[10] merkleProof;
        bytes32 leafNextValue;
        bytes8 leafNextIdx;
        bytes32[4] pubInputs;
    }

    function verifyPubInputs(
        ProtocolInclusionProof calldata protocolInclusionProof,
        bytes32 vKeyHash,
        address quantum_verifier
    ) internal {
        assembly {
            let p := mload(0x40)

            // reduced pub inputs = compute keccak(protocolVKeyHash || pubInputs...)
            mstore(p, calldataload(0x4))
            mstore(add(p, 0x20), calldataload(0x1e4))
            mstore(add(p, 0x40), calldataload(0x204))
            mstore(add(p, 0x60), calldataload(0x224))
            mstore(add(p, 0x80), calldataload(0x244))
            mstore(add(p, 0x60), keccak256(p, 0xa0))

            // pad reduced pub inputs
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

            mstore(p, calldataload(0x44)) // load merkle-proof-position at `p`

            // computing root (at `p+0x40`) using 10 proof elms and their position
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

library ProtocolVerifier_5 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE = 0xc19d93fb;

    struct ProtocolInclusionProof {
        bytes32 protocolVKeyHash;
        bytes32 reductionVKeyHash;
        uint256 merkleProofPosition;
        bytes32[10] merkleProof;
        bytes32 leafNextValue;
        bytes8 leafNextIdx;
        bytes32[5] pubInputs;
    }

    function verifyPubInputs(
        ProtocolInclusionProof calldata protocolInclusionProof,
        bytes32 vKeyHash,
        address quantum_verifier
    ) internal {
        assembly {
            let p := mload(0x40)

            // reduced pub inputs = compute keccak(protocolVKeyHash || pubInputs...)
            mstore(p, calldataload(0x4))
            mstore(add(p, 0x20), calldataload(0x1e4))
            mstore(add(p, 0x40), calldataload(0x204))
            mstore(add(p, 0x60), calldataload(0x224))
            mstore(add(p, 0x80), calldataload(0x244))
            mstore(add(p, 0xa0), calldataload(0x264))
            mstore(add(p, 0x60), keccak256(p, 0xc0))

            // pad reduced pub inputs
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

            mstore(p, calldataload(0x44)) // load merkle-proof-position at `p`

            // computing root (at `p+0x40`) using 10 proof elms and their position
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

library ProtocolVerifier_6 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE = 0xc19d93fb;

    struct ProtocolInclusionProof {
        bytes32 protocolVKeyHash;
        bytes32 reductionVKeyHash;
        uint256 merkleProofPosition;
        bytes32[10] merkleProof;
        bytes32 leafNextValue;
        bytes8 leafNextIdx;
        bytes32[6] pubInputs;
    }

    function verifyPubInputs(
        ProtocolInclusionProof calldata protocolInclusionProof,
        bytes32 vKeyHash,
        address quantum_verifier
    ) internal {
        assembly {
            let p := mload(0x40)

            // reduced pub inputs = compute keccak(protocolVKeyHash || pubInputs...)
            mstore(p, calldataload(0x4))
            mstore(add(p, 0x20), calldataload(0x1e4))
            mstore(add(p, 0x40), calldataload(0x204))
            mstore(add(p, 0x60), calldataload(0x224))
            mstore(add(p, 0x80), calldataload(0x244))
            mstore(add(p, 0xa0), calldataload(0x264))
            mstore(add(p, 0xc0), calldataload(0x284))
            mstore(add(p, 0x60), keccak256(p, 0xe0))

            // pad reduced pub inputs
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

            mstore(p, calldataload(0x44)) // load merkle-proof-position at `p`

            // computing root (at `p+0x40`) using 10 proof elms and their position
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

library ProtocolVerifier_7 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE = 0xc19d93fb;

    struct ProtocolInclusionProof {
        bytes32 protocolVKeyHash;
        bytes32 reductionVKeyHash;
        uint256 merkleProofPosition;
        bytes32[10] merkleProof;
        bytes32 leafNextValue;
        bytes8 leafNextIdx;
        bytes32[7] pubInputs;
    }

    function verifyPubInputs(
        ProtocolInclusionProof calldata protocolInclusionProof,
        bytes32 vKeyHash,
        address quantum_verifier
    ) internal {
        assembly {
            let p := mload(0x40)

            // reduced pub inputs = compute keccak(protocolVKeyHash || pubInputs...)
            mstore(p, calldataload(0x4))
            mstore(add(p, 0x20), calldataload(0x1e4))
            mstore(add(p, 0x40), calldataload(0x204))
            mstore(add(p, 0x60), calldataload(0x224))
            mstore(add(p, 0x80), calldataload(0x244))
            mstore(add(p, 0xa0), calldataload(0x264))
            mstore(add(p, 0xc0), calldataload(0x284))
            mstore(add(p, 0xe0), calldataload(0x2a4))
            mstore(add(p, 0x60), keccak256(p, 0x100))

            // pad reduced pub inputs
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

            mstore(p, calldataload(0x44)) // load merkle-proof-position at `p`

            // computing root (at `p+0x40`) using 10 proof elms and their position
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

library ProtocolVerifier_8 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE = 0xc19d93fb;

    struct ProtocolInclusionProof {
        bytes32 protocolVKeyHash;
        bytes32 reductionVKeyHash;
        uint256 merkleProofPosition;
        bytes32[10] merkleProof;
        bytes32 leafNextValue;
        bytes8 leafNextIdx;
        bytes32[8] pubInputs;
    }

    function verifyPubInputs(
        ProtocolInclusionProof calldata protocolInclusionProof,
        bytes32 vKeyHash,
        address quantum_verifier
    ) internal {
        assembly {
            let p := mload(0x40)

            // reduced pub inputs = compute keccak(protocolVKeyHash || pubInputs...)
            mstore(p, calldataload(0x4))
            mstore(add(p, 0x20), calldataload(0x1e4))
            mstore(add(p, 0x40), calldataload(0x204))
            mstore(add(p, 0x60), calldataload(0x224))
            mstore(add(p, 0x80), calldataload(0x244))
            mstore(add(p, 0xa0), calldataload(0x264))
            mstore(add(p, 0xc0), calldataload(0x284))
            mstore(add(p, 0xe0), calldataload(0x2a4))
            mstore(add(p, 0x100), calldataload(0x2c4))
            mstore(add(p, 0x60), keccak256(p, 0x120))

            // pad reduced pub inputs
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

            mstore(p, calldataload(0x44)) // load merkle-proof-position at `p`

            // computing root (at `p+0x40`) using 10 proof elms and their position
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

library ProtocolVerifier_9 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE = 0xc19d93fb;

    struct ProtocolInclusionProof {
        bytes32 protocolVKeyHash;
        bytes32 reductionVKeyHash;
        uint256 merkleProofPosition;
        bytes32[10] merkleProof;
        bytes32 leafNextValue;
        bytes8 leafNextIdx;
        bytes32[9] pubInputs;
    }

    function verifyPubInputs(
        ProtocolInclusionProof calldata protocolInclusionProof,
        bytes32 vKeyHash,
        address quantum_verifier
    ) internal {
        assembly {
            let p := mload(0x40)

            // reduced pub inputs = compute keccak(protocolVKeyHash || pubInputs...)
            mstore(p, calldataload(0x4))
            mstore(add(p, 0x20), calldataload(0x1e4))
            mstore(add(p, 0x40), calldataload(0x204))
            mstore(add(p, 0x60), calldataload(0x224))
            mstore(add(p, 0x80), calldataload(0x244))
            mstore(add(p, 0xa0), calldataload(0x264))
            mstore(add(p, 0xc0), calldataload(0x284))
            mstore(add(p, 0xe0), calldataload(0x2a4))
            mstore(add(p, 0x100), calldataload(0x2c4))
            mstore(add(p, 0x120), calldataload(0x2e4))
            mstore(add(p, 0x60), keccak256(p, 0x140))

            // pad reduced pub inputs
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

            mstore(p, calldataload(0x44)) // load merkle-proof-position at `p`

            // computing root (at `p+0x40`) using 10 proof elms and their position
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

library ProtocolVerifier_10 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE = 0xc19d93fb;

    struct ProtocolInclusionProof {
        bytes32 protocolVKeyHash;
        bytes32 reductionVKeyHash;
        uint256 merkleProofPosition;
        bytes32[10] merkleProof;
        bytes32 leafNextValue;
        bytes8 leafNextIdx;
        bytes32[10] pubInputs;
    }

    function verifyPubInputs(
        ProtocolInclusionProof calldata protocolInclusionProof,
        bytes32 vKeyHash,
        address quantum_verifier
    ) internal {
        assembly {
            let p := mload(0x40)

            // reduced pub inputs = compute keccak(protocolVKeyHash || pubInputs...)
            mstore(p, calldataload(0x4))
            mstore(add(p, 0x20), calldataload(0x1e4))
            mstore(add(p, 0x40), calldataload(0x204))
            mstore(add(p, 0x60), calldataload(0x224))
            mstore(add(p, 0x80), calldataload(0x244))
            mstore(add(p, 0xa0), calldataload(0x264))
            mstore(add(p, 0xc0), calldataload(0x284))
            mstore(add(p, 0xe0), calldataload(0x2a4))
            mstore(add(p, 0x100), calldataload(0x2c4))
            mstore(add(p, 0x120), calldataload(0x2e4))
            mstore(add(p, 0x140), calldataload(0x304))
            mstore(add(p, 0x60), keccak256(p, 0x160))

            // pad reduced pub inputs
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

            mstore(p, calldataload(0x44)) // load merkle-proof-position at `p`

            // computing root (at `p+0x40`) using 10 proof elms and their position
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

library ProtocolVerifier_11 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE = 0xc19d93fb;

    struct ProtocolInclusionProof {
        bytes32 protocolVKeyHash;
        bytes32 reductionVKeyHash;
        uint256 merkleProofPosition;
        bytes32[10] merkleProof;
        bytes32 leafNextValue;
        bytes8 leafNextIdx;
        bytes32[11] pubInputs;
    }

    function verifyPubInputs(
        ProtocolInclusionProof calldata protocolInclusionProof,
        bytes32 vKeyHash,
        address quantum_verifier
    ) internal {
        assembly {
            let p := mload(0x40)

            // reduced pub inputs = compute keccak(protocolVKeyHash || pubInputs...)
            mstore(p, calldataload(0x4))
            mstore(add(p, 0x20), calldataload(0x1e4))
            mstore(add(p, 0x40), calldataload(0x204))
            mstore(add(p, 0x60), calldataload(0x224))
            mstore(add(p, 0x80), calldataload(0x244))
            mstore(add(p, 0xa0), calldataload(0x264))
            mstore(add(p, 0xc0), calldataload(0x284))
            mstore(add(p, 0xe0), calldataload(0x2a4))
            mstore(add(p, 0x100), calldataload(0x2c4))
            mstore(add(p, 0x120), calldataload(0x2e4))
            mstore(add(p, 0x140), calldataload(0x304))
            mstore(add(p, 0x160), calldataload(0x324))
            mstore(add(p, 0x60), keccak256(p, 0x180))

            // pad reduced pub inputs
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

            mstore(p, calldataload(0x44)) // load merkle-proof-position at `p`

            // computing root (at `p+0x40`) using 10 proof elms and their position
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

library ProtocolVerifier_12 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE = 0xc19d93fb;

    struct ProtocolInclusionProof {
        bytes32 protocolVKeyHash;
        bytes32 reductionVKeyHash;
        uint256 merkleProofPosition;
        bytes32[10] merkleProof;
        bytes32 leafNextValue;
        bytes8 leafNextIdx;
        bytes32[12] pubInputs;
    }

    function verifyPubInputs(
        ProtocolInclusionProof calldata protocolInclusionProof,
        bytes32 vKeyHash,
        address quantum_verifier
    ) internal {
        assembly {
            let p := mload(0x40)

            // reduced pub inputs = compute keccak(protocolVKeyHash || pubInputs...)
            mstore(p, calldataload(0x4))
            mstore(add(p, 0x20), calldataload(0x1e4))
            mstore(add(p, 0x40), calldataload(0x204))
            mstore(add(p, 0x60), calldataload(0x224))
            mstore(add(p, 0x80), calldataload(0x244))
            mstore(add(p, 0xa0), calldataload(0x264))
            mstore(add(p, 0xc0), calldataload(0x284))
            mstore(add(p, 0xe0), calldataload(0x2a4))
            mstore(add(p, 0x100), calldataload(0x2c4))
            mstore(add(p, 0x120), calldataload(0x2e4))
            mstore(add(p, 0x140), calldataload(0x304))
            mstore(add(p, 0x160), calldataload(0x324))
            mstore(add(p, 0x180), calldataload(0x344))
            mstore(add(p, 0x60), keccak256(p, 0x1a0))

            // pad reduced pub inputs
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

            mstore(p, calldataload(0x44)) // load merkle-proof-position at `p`

            // computing root (at `p+0x40`) using 10 proof elms and their position
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

library ProtocolVerifier_13 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE = 0xc19d93fb;

    struct ProtocolInclusionProof {
        bytes32 protocolVKeyHash;
        bytes32 reductionVKeyHash;
        uint256 merkleProofPosition;
        bytes32[10] merkleProof;
        bytes32 leafNextValue;
        bytes8 leafNextIdx;
        bytes32[13] pubInputs;
    }

    function verifyPubInputs(
        ProtocolInclusionProof calldata protocolInclusionProof,
        bytes32 vKeyHash,
        address quantum_verifier
    ) internal {
        assembly {
            let p := mload(0x40)

            // reduced pub inputs = compute keccak(protocolVKeyHash || pubInputs...)
            mstore(p, calldataload(0x4))
            mstore(add(p, 0x20), calldataload(0x1e4))
            mstore(add(p, 0x40), calldataload(0x204))
            mstore(add(p, 0x60), calldataload(0x224))
            mstore(add(p, 0x80), calldataload(0x244))
            mstore(add(p, 0xa0), calldataload(0x264))
            mstore(add(p, 0xc0), calldataload(0x284))
            mstore(add(p, 0xe0), calldataload(0x2a4))
            mstore(add(p, 0x100), calldataload(0x2c4))
            mstore(add(p, 0x120), calldataload(0x2e4))
            mstore(add(p, 0x140), calldataload(0x304))
            mstore(add(p, 0x160), calldataload(0x324))
            mstore(add(p, 0x180), calldataload(0x344))
            mstore(add(p, 0x1a0), calldataload(0x364))
            mstore(add(p, 0x60), keccak256(p, 0x1c0))

            // pad reduced pub inputs
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

            mstore(p, calldataload(0x44)) // load merkle-proof-position at `p`

            // computing root (at `p+0x40`) using 10 proof elms and their position
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

library ProtocolVerifier_14 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE = 0xc19d93fb;

    struct ProtocolInclusionProof {
        bytes32 protocolVKeyHash;
        bytes32 reductionVKeyHash;
        uint256 merkleProofPosition;
        bytes32[10] merkleProof;
        bytes32 leafNextValue;
        bytes8 leafNextIdx;
        bytes32[14] pubInputs;
    }

    function verifyPubInputs(
        ProtocolInclusionProof calldata protocolInclusionProof,
        bytes32 vKeyHash,
        address quantum_verifier
    ) internal {
        assembly {
            let p := mload(0x40)

            // reduced pub inputs = compute keccak(protocolVKeyHash || pubInputs...)
            mstore(p, calldataload(0x4))
            mstore(add(p, 0x20), calldataload(0x1e4))
            mstore(add(p, 0x40), calldataload(0x204))
            mstore(add(p, 0x60), calldataload(0x224))
            mstore(add(p, 0x80), calldataload(0x244))
            mstore(add(p, 0xa0), calldataload(0x264))
            mstore(add(p, 0xc0), calldataload(0x284))
            mstore(add(p, 0xe0), calldataload(0x2a4))
            mstore(add(p, 0x100), calldataload(0x2c4))
            mstore(add(p, 0x120), calldataload(0x2e4))
            mstore(add(p, 0x140), calldataload(0x304))
            mstore(add(p, 0x160), calldataload(0x324))
            mstore(add(p, 0x180), calldataload(0x344))
            mstore(add(p, 0x1a0), calldataload(0x364))
            mstore(add(p, 0x1c0), calldataload(0x384))
            mstore(add(p, 0x60), keccak256(p, 0x1e0))

            // pad reduced pub inputs
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

            mstore(p, calldataload(0x44)) // load merkle-proof-position at `p`

            // computing root (at `p+0x40`) using 10 proof elms and their position
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

library ProtocolVerifier_15 {
    uint256 constant ONE = 0x01;
    uint256 constant SIGNATURE = 0xc19d93fb;

    struct ProtocolInclusionProof {
        bytes32 protocolVKeyHash;
        bytes32 reductionVKeyHash;
        uint256 merkleProofPosition;
        bytes32[10] merkleProof;
        bytes32 leafNextValue;
        bytes8 leafNextIdx;
        bytes32[15] pubInputs;
    }

    function verifyPubInputs(
        ProtocolInclusionProof calldata protocolInclusionProof,
        bytes32 vKeyHash,
        address quantum_verifier
    ) internal {
        assembly {
            let p := mload(0x40)

            // reduced pub inputs = compute keccak(protocolVKeyHash || pubInputs...)
            mstore(p, calldataload(0x4))
            mstore(add(p, 0x20), calldataload(0x1e4))
            mstore(add(p, 0x40), calldataload(0x204))
            mstore(add(p, 0x60), calldataload(0x224))
            mstore(add(p, 0x80), calldataload(0x244))
            mstore(add(p, 0xa0), calldataload(0x264))
            mstore(add(p, 0xc0), calldataload(0x284))
            mstore(add(p, 0xe0), calldataload(0x2a4))
            mstore(add(p, 0x100), calldataload(0x2c4))
            mstore(add(p, 0x120), calldataload(0x2e4))
            mstore(add(p, 0x140), calldataload(0x304))
            mstore(add(p, 0x160), calldataload(0x324))
            mstore(add(p, 0x180), calldataload(0x344))
            mstore(add(p, 0x1a0), calldataload(0x364))
            mstore(add(p, 0x1c0), calldataload(0x384))
            mstore(add(p, 0x1e0), calldataload(0x3a4))
            mstore(add(p, 0x60), keccak256(p, 0x200))

            // pad reduced pub inputs
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

            mstore(p, calldataload(0x44)) // load merkle-proof-position at `p`

            // computing root (at `p+0x40`) using 10 proof elms and their position
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
