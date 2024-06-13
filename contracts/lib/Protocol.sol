// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ProtocolVerifier_2} from "./ProtocolVerifier.sol";
import {ProtocolVerifier_4} from "./ProtocolVerifier.sol";

// application contract
contract Protocol_2 is Initializable {
    address constant QUANTUM_VERIFIER =
        0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512;

    bytes32 vKeyHash;

    function initialize(bytes32 vKeyHash_) public initializer {
        vKeyHash = vKeyHash_;
    }

    function verifyPubInputs(
        ProtocolVerifier_2.ProtocolInclusionProof
            calldata protocolInclusionProof
    ) external {
        ProtocolVerifier_2.verifyPubInputs(
            protocolInclusionProof,
            vKeyHash,
            QUANTUM_VERIFIER
        );
    }
}

contract Protocol_4 is Initializable {
    address constant QUANTUM_VERIFIER =
        0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512;

    bytes32 vKeyHash;

    function initialize(bytes32 vKeyHash_) public initializer {
        vKeyHash = vKeyHash_;
    }

    function verifyPubInputs(
        ProtocolVerifier_4.ProtocolInclusionProof
            calldata protocolInclusionProof
    ) external {
        ProtocolVerifier_4.verifyPubInputs(
            protocolInclusionProof,
            vKeyHash,
            QUANTUM_VERIFIER
        );
    }
}
