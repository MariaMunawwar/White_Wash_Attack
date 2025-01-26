// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract DeviceContractRegistry {
    mapping(bytes32 => bool) public registeredIPHashes;

    // Function to store a hash of the IP address
    function storeIPHash(bytes32 ipHash) public {
        require(!registeredIPHashes[ipHash], "IP already registered");
        registeredIPHashes[ipHash] = true;
    }

    // Function to verify if an IP address hash is registered
    function verifyIPHash(bytes32 ipHash) public view returns (bool) {
        return registeredIPHashes[ipHash];
    }
}
