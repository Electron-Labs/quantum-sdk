// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

library ProtocolVerifier_1 {
    uint256 constant SIGNATURE = 0x70e8daf7;

    function verifyPubInputs(
        uint256[1] calldata pubInputs,
        bytes32 vkHash,
        address quantum_verifier
    ) internal {
        assembly {
            let p := mload(0x40)
            mstore(add(p, 0x40), calldataload(0x4))
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x20))
            mstore(add(p, 0x20), vkHash)
            mstore(p, SIGNATURE)
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
}

library ProtocolVerifier_2 {
    uint256 constant SIGNATURE = 0x70e8daf7;

    function verifyPubInputs(
        uint256[2] calldata pubInputs,
        bytes32 vkHash,
        address quantum_verifier
    ) internal {
        assembly {
            let p := mload(0x40)
            mstore(add(p, 0x40), calldataload(0x4))
            mstore(add(p, 0x60), calldataload(0x24))
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
            mstore(add(p, 0x20), vkHash)
            mstore(p, SIGNATURE)
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
}

library ProtocolVerifier_3 {
    uint256 constant SIGNATURE = 0x70e8daf7;

    function verifyPubInputs(
        uint256[3] calldata pubInputs,
        bytes32 vkHash,
        address quantum_verifier
    ) internal {
        assembly {
            let p := mload(0x40)
            mstore(add(p, 0x40), calldataload(0x4))
            mstore(add(p, 0x60), calldataload(0x24))
            mstore(add(p, 0x80), calldataload(0x44))
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x60))
            mstore(add(p, 0x20), vkHash)
            mstore(p, SIGNATURE)
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
}

library ProtocolVerifier_4 {
    uint256 constant SIGNATURE = 0x70e8daf7;

    function verifyPubInputs(
        uint256[4] calldata pubInputs,
        bytes32 vkHash,
        address quantum_verifier
    ) internal {
        assembly {
            let p := mload(0x40)
            mstore(add(p, 0x40), calldataload(0x4))
            mstore(add(p, 0x60), calldataload(0x24))
            mstore(add(p, 0x80), calldataload(0x44))
            mstore(add(p, 0xa0), calldataload(0x64))
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x80))
            mstore(add(p, 0x20), vkHash)
            mstore(p, SIGNATURE)
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
}

library ProtocolVerifier_5 {
    uint256 constant SIGNATURE = 0x70e8daf7;

    function verifyPubInputs(
        uint256[5] calldata pubInputs,
        bytes32 vkHash,
        address quantum_verifier
    ) internal {
        assembly {
            let p := mload(0x40)
            mstore(add(p, 0x40), calldataload(0x4))
            mstore(add(p, 0x60), calldataload(0x24))
            mstore(add(p, 0x80), calldataload(0x44))
            mstore(add(p, 0xa0), calldataload(0x64))
            mstore(add(p, 0xc0), calldataload(0x84))
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0xa0))
            mstore(add(p, 0x20), vkHash)
            mstore(p, SIGNATURE)
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
}

library ProtocolVerifier_6 {
    uint256 constant SIGNATURE = 0x70e8daf7;

    function verifyPubInputs(
        uint256[6] calldata pubInputs,
        bytes32 vkHash,
        address quantum_verifier
    ) internal {
        assembly {
            let p := mload(0x40)
            mstore(add(p, 0x40), calldataload(0x4))
            mstore(add(p, 0x60), calldataload(0x24))
            mstore(add(p, 0x80), calldataload(0x44))
            mstore(add(p, 0xa0), calldataload(0x64))
            mstore(add(p, 0xc0), calldataload(0x84))
            mstore(add(p, 0xe0), calldataload(0xa4))
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0xc0))
            mstore(add(p, 0x20), vkHash)
            mstore(p, SIGNATURE)
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
}

library ProtocolVerifier_7 {
    uint256 constant SIGNATURE = 0x70e8daf7;

    function verifyPubInputs(
        uint256[7] calldata pubInputs,
        bytes32 vkHash,
        address quantum_verifier
    ) internal {
        assembly {
            let p := mload(0x40)
            mstore(add(p, 0x40), calldataload(0x4))
            mstore(add(p, 0x60), calldataload(0x24))
            mstore(add(p, 0x80), calldataload(0x44))
            mstore(add(p, 0xa0), calldataload(0x64))
            mstore(add(p, 0xc0), calldataload(0x84))
            mstore(add(p, 0xe0), calldataload(0xa4))
            mstore(add(p, 0x100), calldataload(0xc4))
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0xe0))
            mstore(add(p, 0x20), vkHash)
            mstore(p, SIGNATURE)
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
}

library ProtocolVerifier_8 {
    uint256 constant SIGNATURE = 0x70e8daf7;

    function verifyPubInputs(
        uint256[8] calldata pubInputs,
        bytes32 vkHash,
        address quantum_verifier
    ) internal {
        assembly {
            let p := mload(0x40)
            mstore(add(p, 0x40), calldataload(0x4))
            mstore(add(p, 0x60), calldataload(0x24))
            mstore(add(p, 0x80), calldataload(0x44))
            mstore(add(p, 0xa0), calldataload(0x64))
            mstore(add(p, 0xc0), calldataload(0x84))
            mstore(add(p, 0xe0), calldataload(0xa4))
            mstore(add(p, 0x100), calldataload(0xc4))
            mstore(add(p, 0x120), calldataload(0xe4))
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x100))
            mstore(add(p, 0x20), vkHash)
            mstore(p, SIGNATURE)
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
}

library ProtocolVerifier_9 {
    uint256 constant SIGNATURE = 0x70e8daf7;

    function verifyPubInputs(
        uint256[9] calldata pubInputs,
        bytes32 vkHash,
        address quantum_verifier
    ) internal {
        assembly {
            let p := mload(0x40)
            mstore(add(p, 0x40), calldataload(0x4))
            mstore(add(p, 0x60), calldataload(0x24))
            mstore(add(p, 0x80), calldataload(0x44))
            mstore(add(p, 0xa0), calldataload(0x64))
            mstore(add(p, 0xc0), calldataload(0x84))
            mstore(add(p, 0xe0), calldataload(0xa4))
            mstore(add(p, 0x100), calldataload(0xc4))
            mstore(add(p, 0x120), calldataload(0xe4))
            mstore(add(p, 0x140), calldataload(0x104))
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x120))
            mstore(add(p, 0x20), vkHash)
            mstore(p, SIGNATURE)
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
}

library ProtocolVerifier_10 {
    uint256 constant SIGNATURE = 0x70e8daf7;

    function verifyPubInputs(
        uint256[10] calldata pubInputs,
        bytes32 vkHash,
        address quantum_verifier
    ) internal {
        assembly {
            let p := mload(0x40)
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
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x140))
            mstore(add(p, 0x20), vkHash)
            mstore(p, SIGNATURE)
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
}

library ProtocolVerifier_11 {
    uint256 constant SIGNATURE = 0x70e8daf7;

    function verifyPubInputs(
        uint256[11] calldata pubInputs,
        bytes32 vkHash,
        address quantum_verifier
    ) internal {
        assembly {
            let p := mload(0x40)
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
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x160))
            mstore(add(p, 0x20), vkHash)
            mstore(p, SIGNATURE)
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
}

library ProtocolVerifier_12 {
    uint256 constant SIGNATURE = 0x70e8daf7;

    function verifyPubInputs(
        uint256[12] calldata pubInputs,
        bytes32 vkHash,
        address quantum_verifier
    ) internal {
        assembly {
            let p := mload(0x40)
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
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x180))
            mstore(add(p, 0x20), vkHash)
            mstore(p, SIGNATURE)
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
}

library ProtocolVerifier_13 {
    uint256 constant SIGNATURE = 0x70e8daf7;

    function verifyPubInputs(
        uint256[13] calldata pubInputs,
        bytes32 vkHash,
        address quantum_verifier
    ) internal {
        assembly {
            let p := mload(0x40)
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
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x1a0))
            mstore(add(p, 0x20), vkHash)
            mstore(p, SIGNATURE)
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
}

library ProtocolVerifier_14 {
    uint256 constant SIGNATURE = 0x70e8daf7;

    function verifyPubInputs(
        uint256[14] calldata pubInputs,
        bytes32 vkHash,
        address quantum_verifier
    ) internal {
        assembly {
            let p := mload(0x40)
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
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x1c0))
            mstore(add(p, 0x20), vkHash)
            mstore(p, SIGNATURE)
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
}

library ProtocolVerifier_15 {
    uint256 constant SIGNATURE = 0x70e8daf7;

    function verifyPubInputs(
        uint256[15] calldata pubInputs,
        bytes32 vkHash,
        address quantum_verifier
    ) internal {
        assembly {
            let p := mload(0x40)
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
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x1e0))
            mstore(add(p, 0x20), vkHash)
            mstore(p, SIGNATURE)
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
}
