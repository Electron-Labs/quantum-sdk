// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {ProtocolVerifier_2, ProtocolVerifier_4} from "./ProtocolVerifier.sol";

contract Protocol {
    bytes32 vkHash;
    address constant QUANTUM = 0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0;

    uint256 constant SIGNATURE = 0x70e8daf7;

    constructor(bytes32 vkHash_) {
        vkHash = vkHash_;
    }

    function verifyPubInputs_2(uint256[2] calldata pubInputs) external {
        ProtocolVerifier_2.verifyPubInputs(pubInputs, vkHash, QUANTUM);
    }
    function verifyPubInputs_4(uint256[4] calldata pubInputs) external {
        ProtocolVerifier_4.verifyPubInputs(pubInputs, vkHash, QUANTUM);
    }
}
