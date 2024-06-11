// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ProtocolVerifier_2} from "./ProtocolVerifier.sol";

// application contract
contract Protocol is Initializable {
    bytes32 vKeyHash;

    function initialize(bytes32 vKeyHash_) public initializer {
        vKeyHash = vKeyHash_;
    }

    function verifyPubInputs(
        ProtocolVerifier_2.QuantumProof calldata quantumProof
    ) external {
        ProtocolVerifier_2.verifyPubInputs(quantumProof, vKeyHash);
    }
}
