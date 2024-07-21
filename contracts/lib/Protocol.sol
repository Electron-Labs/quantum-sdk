// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {ProtocolVerifier_2, ProtocolVerifier_5} from "./ProtocolVerifier.sol";

contract Protocol {
    bytes32 vkHash;
    address constant QUANTUM = 0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0;

    constructor(bytes32 vkHash_) {
        vkHash = vkHash_;
    }

    function verifyLatestPubInputs_2(uint256[2] calldata pubInputs) external {
        ProtocolVerifier_2.verifyLatestPubInputs(pubInputs, vkHash, QUANTUM);
    }

    function verifyOldPubInputs_2(
        ProtocolVerifier_2.ProtocolInclusionProof
            calldata protocolInclusionProof,
        uint256[2] calldata pubInputs
    ) external {
        ProtocolVerifier_2.verifyOldPubInputs(
            protocolInclusionProof,
            pubInputs,
            vkHash,
            QUANTUM
        );
    }

    function verifyLatestPubInputs_5(uint256[5] calldata pubInputs) external {
        ProtocolVerifier_5.verifyLatestPubInputs(pubInputs, vkHash, QUANTUM);
    }

    function verifyOldPubInputs_5(
        ProtocolVerifier_5.ProtocolInclusionProof
            calldata protocolInclusionProof,
        uint256[5] calldata pubInputs
    ) external {
        ProtocolVerifier_5.verifyOldPubInputs(
            protocolInclusionProof,
            pubInputs,
            vkHash,
            QUANTUM
        );
    }
}
