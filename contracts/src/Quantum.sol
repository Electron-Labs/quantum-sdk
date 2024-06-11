// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract Quantum is Initializable {
    bytes32 public state;

    function initialize(bytes32 initState) public initializer {
        state = initState;
    }
}
