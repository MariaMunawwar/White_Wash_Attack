// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract SmartIdentity {
    struct Device {
        bytes32 ipHash;
        bytes32 imeiHash;
        bytes32 macHash;
        bool isBlacklisted;
    }

    // Malicious user data structure
    struct MaliciousData {
        bool isBlacklisted;
        uint256 deviationCount;
        uint256 lastDeviationTime;
        string reason;
        string banType; // NEW: Track ban type (malicious_behavior, poor_performance)
    }

    // Mapping to store devices based on their IMEI hash
    mapping(bytes32 => Device) public devices;

    // Mapping to store blacklisted IPs
    mapping(bytes32 => bool) public blacklistedIPs;

    // Array to keep track of all blacklisted IPs (hashes)
    bytes32[] public allBlacklistedIPHashes;

    // Mapping to store malicious users
    mapping(bytes32 => MaliciousData) public maliciousUsers;

    // Array to keep track of all malicious user hashes
    bytes32[] public allMaliciousUserHashes;

    // Events for malicious user detection
    event MaliciousUserDetected(
        bytes32 indexed userHash,
        uint256 deviationCount,
        string reason,
        string banType
    );

    event UserPermanentlyBanned(
        bytes32 indexed userHash,
        string reason,
        string banType
    );

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

    // EXISTING: Function to flag a user as malicious (for deviation-based bans)
    function flagMaliciousUser(
        bytes32 userHash,
        uint256 deviationCount,
        string memory reason
    ) external {
        // Update malicious user data
        maliciousUsers[userHash] = MaliciousData({
            isBlacklisted: deviationCount >= 3, // Keep original logic for malicious behavior
            deviationCount: deviationCount,
            lastDeviationTime: block.timestamp,
            reason: reason,
            banType: "malicious_behavior"
        });

        // Add to malicious users array if banned
        if (deviationCount >= 3) {
            _addToMaliciousArray(userHash);
            emit UserPermanentlyBanned(userHash, reason, "malicious_behavior");
        }
        
        emit MaliciousUserDetected(userHash, deviationCount, reason, "malicious_behavior");
    }

    // NEW: Function to immediately ban a user (for poor performance, etc.)
    function banUserImmediately(
        bytes32 userHash,
        string memory reason,
        string memory banType
    ) external {
        // Immediately ban the user regardless of deviation count
        maliciousUsers[userHash] = MaliciousData({
            isBlacklisted: true, // Always true for immediate bans
            deviationCount: 1, // Set to 1 to indicate this is not deviation-based
            lastDeviationTime: block.timestamp,
            reason: reason,
            banType: banType
        });

        // Add to malicious users array
        _addToMaliciousArray(userHash);
        
        emit UserPermanentlyBanned(userHash, reason, banType);
        emit MaliciousUserDetected(userHash, 1, reason, banType);
    }

    // HELPER: Internal function to add user to malicious array (avoid duplicates)
    function _addToMaliciousArray(bytes32 userHash) internal {
        bool alreadyExists = false;
        for (uint i = 0; i < allMaliciousUserHashes.length; i++) {
            if (allMaliciousUserHashes[i] == userHash) {
                alreadyExists = true;
                break;
            }
        }
        if (!alreadyExists) {
            allMaliciousUserHashes.push(userHash);
        }
    }

    // Function to check if a user is malicious
    function isMaliciousUser(bytes32 userHash) external view returns (bool) {
        return maliciousUsers[userHash].isBlacklisted;
    }

    // UPDATED: Function to get malicious user details (now includes ban type)
    function getMaliciousUserDetails(bytes32 userHash) external view returns (
        bool isBlacklisted,
        uint256 deviationCount,
        uint256 lastDeviationTime,
        string memory reason,
        string memory banType
    ) {
        MaliciousData memory userData = maliciousUsers[userHash];
        return (
            userData.isBlacklisted,
            userData.deviationCount,
            userData.lastDeviationTime,
            userData.reason,
            userData.banType
        );
    }

    // Function to get all malicious users
    function getAllMaliciousUsers() external view returns (bytes32[] memory) {
        return allMaliciousUserHashes;
    }

    // Function to get total count of malicious users
    function getMaliciousUserCount() external view returns (uint256) {
        return allMaliciousUserHashes.length;
    }

    // NEW: Function to get users by ban type
    function getUsersByBanType(string memory banType) external view returns (bytes32[] memory) {
        bytes32[] memory result = new bytes32[](allMaliciousUserHashes.length);
        uint256 count = 0;
        
        for (uint256 i = 0; i < allMaliciousUserHashes.length; i++) {
            bytes32 userHash = allMaliciousUserHashes[i];
            if (keccak256(abi.encodePacked(maliciousUsers[userHash].banType)) == keccak256(abi.encodePacked(banType))) {
                result[count] = userHash;
                count++;
            }
        }
        
        // Resize array to actual count
        bytes32[] memory finalResult = new bytes32[](count);
        for (uint256 i = 0; i < count; i++) {
            finalResult[i] = result[i];
        }
        
        return finalResult;
    }
}