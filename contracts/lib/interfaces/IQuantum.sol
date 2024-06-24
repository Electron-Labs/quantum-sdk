// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IQuantum {
    function pubInputsHashes(bytes32 vkHash) external returns (bytes32 pubInputs);
}
