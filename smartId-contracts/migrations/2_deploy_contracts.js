const SmartIdentity = artifacts.require("SmartIdentity");
const DeviceContractRegistry = artifacts.require("DeviceContractRegistry");

module.exports = function(deployer) {
  deployer.deploy(SmartIdentity);
  deployer.deploy(DeviceContractRegistry);
};
