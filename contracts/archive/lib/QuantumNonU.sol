// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract Quantum {
    bytes32 public state;

    constructor(bytes32 initState) public {
        state = initState;
    }
}
