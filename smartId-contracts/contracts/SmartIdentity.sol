// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract SmartIdentity {
    struct Device {
        bytes32 ipHash;
        bytes32 imeiHash;
        bytes32 macHash;
        bool isBlacklisted;
    }

    // Mapping to store devices based on their IMEI hash
    mapping(bytes32 => Device) public devices;

    // Mapping to store blacklisted IPs
    mapping(bytes32 => bool) public blacklistedIPs;

    // Array to keep track of all blacklisted IPs (hashes)
    bytes32[] public allBlacklistedIPHashes;

    // Function to register a device with IP, IMEI, and MAC hash
    function registerDevice(bytes32 ipHash, bytes32 imeiHash, bytes32 macHash) public {
        require(devices[imeiHash].imeiHash == 0, "Device already registered");

        devices[imeiHash] = Device({
            ipHash: ipHash,
            imeiHash: imeiHash,
            macHash: macHash,
            isBlacklisted: false
        });
    }

    // Function to blacklist a device by its IMEI hash
    function blacklistDevice(bytes32 imeiHash) public {
        require(devices[imeiHash].imeiHash != 0, "Device not found");

        devices[imeiHash].isBlacklisted = true;
        
        // Add the IP to the blacklisted IPs mapping and array if not already present
        bytes32 ipHash = devices[imeiHash].ipHash;
        if (!blacklistedIPs[ipHash]) {
            blacklistedIPs[ipHash] = true;
            allBlacklistedIPHashes.push(ipHash);
        }
    }

    // Function to check if a device is blacklisted
    function isDeviceBlacklisted(bytes32 imeiHash) public view returns (bool) {
        require(devices[imeiHash].imeiHash != 0, "Device not found");
        return devices[imeiHash].isBlacklisted;
    }

    // Function to verify if an IP is blacklisted
    function isIPBlacklisted(bytes32 ipHash) public view returns (bool) {
        return blacklistedIPs[ipHash];
    }

    // Function to retrieve all blacklisted IPs
    function getAllBlacklistedIPs() public view returns (bytes32[] memory) {
        return allBlacklistedIPHashes;
    }

    // Function to get device details
    function getDeviceDetails(bytes32 imeiHash) public view returns (bytes32, bytes32, bytes32, bool) {
        Device memory device = devices[imeiHash];
        return (device.ipHash, device.imeiHash, device.macHash, device.isBlacklisted);
    }
}
