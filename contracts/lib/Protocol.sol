// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {ProtocolVerifier_2} from "./ProtocolVerifier.sol";

contract Protocol {
    bytes32 combinedVKeyHash;
    address constant QUANTUM = 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512;

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
