// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {ProtocolVerifier_14} from "./ProtocolVerifier.sol";

contract Protocol {
    bytes32 combinedVKeyHash;
    address constant QUANTUM = 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512;

    constructor(bytes32 combinedVKeyHash_) {
        combinedVKeyHash = combinedVKeyHash_;
    }

    function verifyPubInputs_14(
        uint256[14] calldata pubInputs,
        uint256 merkleProofPosition,
        bytes32[] calldata merkleProof
    ) external {
        ProtocolVerifier_14.verifyPubInputs_14(
            pubInputs,
            combinedVKeyHash,
            QUANTUM,
            merkleProofPosition,
            merkleProof
        );
    }
}
