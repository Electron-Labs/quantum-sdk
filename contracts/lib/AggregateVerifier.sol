// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {CircuitVerifier} from "./CircuitVerifier.sol";

contract AggregateVerifier {
    address constant QUANTUM = 0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0;

    function verify(
        CircuitVerifier.MerkleProof calldata merkleProof,
        bytes calldata pubInputs,
        bytes32 circuitHash
    ) external view {
        CircuitVerifier.verifyPubInputs(
            merkleProof,
            keccak256(abi.encodePacked(pubInputs)),
            circuitHash,
            QUANTUM
        );
    }

    function verify(
        CircuitVerifier.MerkleProof calldata merkleProof,
        uint256[] calldata pubInputs,
        bytes32 circuitHash
    ) external view {
        CircuitVerifier.verifyPubInputs(
            merkleProof,
            keccak256(abi.encodePacked(pubInputs)),
            circuitHash,
            QUANTUM
        );
    }
}
