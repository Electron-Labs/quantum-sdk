// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IQuantum} from "./interfaces/IQuantum.sol";

// application contract
contract Protocol_4 {
    bytes32 vKHash;
    address constant QUANTUM = 0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0;

    uint256 constant SIGNATURE = 0x70e8daf7;

    constructor(bytes32 vKHash_) {
        vKHash = vKHash_;
    }

    function verifyPubInputs(uint256[4] calldata pubInputs) external {
        assembly {
            let p := mload(0x40)
            mstore(add(p, 0x40), calldataload(0x4))
            mstore(add(p, 0x60), calldataload(0x24))
            mstore(add(p, 0x80), calldataload(0x44))
            mstore(add(p, 0xa0), calldataload(0x64))
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x80))
            mstore(add(p, 0x20), sload(vKHash.slot))
            mstore(p, SIGNATURE)
            let ok := staticcall(gas(), QUANTUM, add(p, 0x1c), 0x24, p, 0x20)
            if iszero(eq(mload(p), mload(add(p, 0x40)))) {
                revert(0, 0)
            }
        }
    }
}

// application contract
contract Protocol_2 {
    bytes32 vKHash;
    address constant QUANTUM = 0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0;

    uint256 constant SIGNATURE = 0x70e8daf7;

    constructor(bytes32 vKHash_) {
        vKHash = vKHash_;
    }

    function verifyPubInputs(uint256[2] calldata pubInputs) external {
        assembly {
            let p := mload(0x40)
            mstore(add(p, 0x40), calldataload(0x4))
            mstore(add(p, 0x60), calldataload(0x24))
            mstore(add(p, 0x40), keccak256(add(p, 0x40), 0x40))
            mstore(add(p, 0x20), sload(vKHash.slot))
            mstore(p, SIGNATURE)
            let ok := staticcall(gas(), QUANTUM, add(p, 0x1c), 0x24, p, 0x20)
            if iszero(eq(mload(p), mload(add(p, 0x40)))) {
                revert(0, 0)
            }
        }
    }
}
