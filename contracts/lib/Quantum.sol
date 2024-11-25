// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract Quantum is Initializable, UUPSUpgradeable, OwnableUpgradeable {
    uint256 constant SIGNATURE = 0xb2ff0a36;

    /// @dev Combined aggregation Vkey
    bytes32 public aggVKey;

    /// @notice The verifier used for proof verification
    address public verifier;

    /// @notice A boolean mapping for all superRoots; a true value indicates the superRoot is verfied
    mapping(bytes32 => bool) public superRootVerified;

    /// @notice A gnark groth16 proof
    struct Proof {
        uint256[8] proof;
        uint256[2] commitments;
        uint256[2] commitmentPok;
    }

    function initialize(
        address verifier_,
        bytes32 aggVKey_
    ) public initializer {
        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();

        verifier = verifier_;
        aggVKey = aggVKey_;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() initializer {}

    /// @notice Submit a super proof; upon successful verification, mark the key `superRoot` in the mapping `superRootVerified` as true
    /// @param proof ZK proof for this `superRoot`
    /// @param superRoot The merkle root for this batch
    function verifySuperproof(
        Proof calldata proof,
        bytes32 superRoot
    ) external {
        assembly {
            let p := mload(0x40)

            // copy superRoot from calldata
            mstore(p, calldataload(0x184))

            // store aggVKey at `p+0x20`
            mstore(add(p, 0x20), sload(aggVKey.slot))

            // pub inputs serialized
            mstore(p, keccak256(p, 0x40))

            // store public inputs just after the proof in the next step
            mstore(add(p, 0x1a0), shr(128, mload(p))) // pub1
            mstore(
                add(p, 0x1c0),
                and(mload(p), 0xffffffffffffffffffffffffffffffff)
            ) // pub2

            // copy proof from calldata
            mstore(add(p, 0x20), calldataload(0x4))
            mstore(add(p, 0x40), calldataload(0x24))
            mstore(add(p, 0x60), calldataload(0x44))
            mstore(add(p, 0x80), calldataload(0x64))
            mstore(add(p, 0xa0), calldataload(0x84))
            mstore(add(p, 0xc0), calldataload(0xa4))
            mstore(add(p, 0xe0), calldataload(0xc4))
            mstore(add(p, 0x100), calldataload(0xe4))
            mstore(add(p, 0x120), calldataload(0x104))
            mstore(add(p, 0x140), calldataload(0x124))
            mstore(add(p, 0x160), calldataload(0x144))
            mstore(add(p, 0x180), calldataload(0x164))

            // store verifyProof's function signature
            mstore(p, SIGNATURE)

            // verify proof
            let verifyOk := staticcall(
                gas(),
                sload(verifier.slot),
                add(p, 0x1c),
                0x1c4,
                0,
                0
            )
            if iszero(verifyOk) {
                revert(0, 0)
            }
        }

        superRootVerified[superRoot] = true;
    }

    /// @notice To update the verifier address
    function setVerifier(address verifierAddress) external onlyOwner {
        verifier = verifierAddress;
    }

    /// @dev To update the Aggregation VKey
    function setAggVKey(bytes32 aggVKey_) external onlyOwner {
        aggVKey = aggVKey_;
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}
}
