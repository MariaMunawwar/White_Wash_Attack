# White-Wash Resilient Blockchain Trust Management System

## Table of Contents
- [Complete Project Demo](#complete-project-demo)
- [Project Overview](#project-overview)
- [Key Features](#key-features)
- [System Requirements](#system-requirements)
- [Installation Guide](#installation-guide)
- [Running the Project](#running-the-project)
- [How the System Works](#how-the-system-works)
  - [Device Registration & User Signup](#device-registration--user-signup)
  - [Logging In](#logging-in)
  - [Trust Score Calculation & Blacklisting](#trust-score-calculation--blacklisting)
  - [Resetting the System](#resetting-the-system)
- [Repository References](#repository-references)
- [License](#license)

## Complete Project Demo
[Watch the system in action](https://youtu.be/zpFr3A-v7ek)

## Project Overview
The White-Wash Resilient Blockchain Trust Management System is designed to prevent whitewashing attacks by implementing blockchain-based device tracking. It ensures secure registration, reputation-based access control, and immutable blacklisting of malicious users to maintain trust and security within the system. 

## Key Features
- Device-based user registration (IP, IMEI, MAC Address)  
- Trust score calculation & dynamic categorization
- Blockchain-secured device verification & blacklisting  
- Service provider/requester roles with dashboards 
- MongoDB backend for secure data storage

## System Requirements  
Ensure the following dependencies are installed before running the project:  

- **Node.js (v20.3.1)** – [Download Here](https://nodejs.org/)  
- **MongoDB** (for database storage) – [Download Here](https://www.mongodb.com/try/download/community)  
- **MongoDB Compass** (for database visualization) – [Download Here](https://www.mongodb.com/products/compass)  
- **Truffle** (for blockchain deployment) – Install via:  
  ```sh
  npm install -g truffle
- **Ganache CLI** (for local Ethereum blockchain) – Install via:
  ```sh
  npm install -g ganache-cli

## Installation Guide  

#### 1. Clone the Repository  
```sh
git clone https://github.com/MariaMunawwar/White_Wash_Attack.git  
cd White_Wash_Attack
```
#### 2. Install Dependencies  
```sh
npm install
```
#### 3. Setup MongoDB  
- Start MongoDB locally.  
- Use **MongoDB Compass** to visualize and manage database entries.
- Connect MongoDB Compass using:
```sh
mongodb://localhost:27017/
```
- Initialize Database:
Make sure the database WhiteWash is created.
Delete old entries from users, feedbacks, logincollections before starting a new simulation.

## Running the Project  

To start the system, open three terminals and follow these steps:  

### Terminal 1: Start Ganache  
```sh
cd White_Wash_Attack  
ganache-cli  
```
### Terminal 2: Deploy Smart Contracts
```sh
cd White_Wash_Attack/smartId-contracts  
truffle compile  
truffle migrate --reset --network development  
```
📌 After deployment, copy the new contract addresses and update app.js:
```sh
const SmartIdentity = new web3.eth.Contract(
    SmartIdentityArtifact.abi, 
    '0xADD_NEW_SMART_IDENTITY_CONTRACT_ADDRESS_HERE'
);
const DeviceContractRegistry = new web3.eth.Contract(
    DeviceContractRegistryArtifact.abi, 
    '0xADD_NEW_DEVICE_CONTRACT_REGISTRY_ADDRESS_HERE'
);
```
### Terminal 3: Start Backend
```sh
cd White_Wash_Attack  
node app.js  
```
### Access the Frontend
Open the following URL in your browser:
```sh
http://127.0.0.1:5500/White_Wash_Attack/frontend/views/login.html
```

## How the System Works

### Device Registration & User Signup

- The `device_identifiers.json` file contains predefined device identities (IP, IMEI, MAC).
- When a user registers:
  - An unassigned device is selected and marked as `"assigned": true`.
  - The user details are stored in MongoDB.
  - The device details are hashed and stored on the blockchain.

### Logging In

The system verifies:

- User existence  
- Password match  
- Blacklist status (checked in MongoDB & Blockchain)  

### Trust Score Calculation & Blacklisting

Users are categorized dynamically based on their Trust Score:

- **Whitelisted** (Score ≥ 70) → Full access.  
- **Greylisted** (30 ≤ Score < 70) → Limited access.  
- **Blacklisted** (Score < 30) → Access Denied.  

- The system updates trust scores based on user interactions and feedback.  
- Blacklisted users cannot log in.  

## Resetting the System

If you need to reset the database for a new simulation:  

1. **Delete old records** from `users`, `logincollections`, and `feedbacks` in MongoDB Compass.  
2. **Reset `device_identifiers.json`**:  
   - Change `"assigned": true` to `"assigned": false`.  
3. **Restart the backend**:  
   ```sh
   cd White_Wash_Attack
   node app.js
   ```

## Repository References

This project integrates the [Smart Identity Contracts](https://github.com/SmartIdentity/smartId-contracts/tree/develop) repository for device registration and blockchain-based trust management.  

For any questions or issues, feel free to contact us or raise an issue in the repository.  

## License

[Apache License 2.0](LICENSE)
