// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {CircuitVerifier} from "../CircuitVerifier.sol";

contract Protocol {
    bytes32 circuitHash;
    address constant QUANTUM = 0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0;

    constructor(bytes32 circuitHash_) {
        circuitHash = circuitHash_;
    }

    function verifyPubInputs(
        uint256[] calldata pubInputs,
        uint256 merkleProofPosition,
        bytes32[] calldata merkleProof
    ) external {
        CircuitVerifier.verifyPubInputs(
            pubInputs,
            merkleProofPosition,
            merkleProof,
            circuitHash,
            QUANTUM
        );
    }
}
