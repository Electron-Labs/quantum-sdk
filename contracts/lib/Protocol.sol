// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {ProtocolVerifier_2} from "./ProtocolVerifier.sol";

contract Protocol {
    bytes32 combinedVKeyHash;
    address constant QUANTUM = 0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0;

    constructor(bytes32 combinedVKeyHash_) {
        combinedVKeyHash = combinedVKeyHash_;
    }

    function verifyPubInputs_2(
        uint256[2] calldata pubInputs,
        uint256 merkleProofPosition,
        bytes32[5] calldata merkleProof
    ) external {
        ProtocolVerifier_2.verifyPubInputs(
            pubInputs,
            merkleProofPosition,
            merkleProof,
            combinedVKeyHash,
            QUANTUM
        );
    }
}
