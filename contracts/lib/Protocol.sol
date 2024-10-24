// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {ProtocolVerifier_5} from "./ProtocolVerifier.sol";

contract Protocol {
    bytes32 combinedVKeyHash;
    address constant QUANTUM = 0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0;

    constructor(bytes32 combinedVKeyHash_) {
        combinedVKeyHash = combinedVKeyHash_;
    }

    function verifyPubInputs_5(
        uint256[5] calldata pubInputs,
        uint256 merkleProofPosition,
        bytes32[] calldata merkleProof
    ) external {
        ProtocolVerifier_5.verifyPubInputs(
            pubInputs,
            merkleProofPosition,
            merkleProof,
            combinedVKeyHash,
            QUANTUM
        );
    }
}
