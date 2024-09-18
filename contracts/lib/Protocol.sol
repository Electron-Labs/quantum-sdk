// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {ProtocolVerifier_14} from "./ProtocolVerifier.sol";

contract Protocol {
    bytes32 vkHash;
    address constant QUANTUM = 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512;

    constructor(bytes32 vkHash_) {
        vkHash = vkHash_;
    }

    function verifyLatestPubInputs_14(uint256[14] calldata pubInputs) external {
        ProtocolVerifier_14.verifyLatestPubInputs(pubInputs, vkHash, QUANTUM);
    }

    function verifyOldPubInputs_14(
        ProtocolVerifier_14.ProtocolInclusionProof
            calldata protocolInclusionProof,
        uint256[14] calldata pubInputs
    ) external {
        ProtocolVerifier_14.verifyOldPubInputs(
            protocolInclusionProof,
            pubInputs,
            vkHash,
            QUANTUM
        );
    }
}
