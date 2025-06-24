require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const fs = require('fs');
//Load and parse the JSON file when a new user is registered:
const deviceIdentifiers = JSON.parse(fs.readFileSync(path.resolve(__dirname, 'device_identifiers.json')));



// Web3 and Truffle setup
const Web3 = require('web3');
const web3 = new Web3('http://localhost:8545'); // Connect to the local Ethereum node or Ganache

const SmartIdentityArtifact = require('./smartId-contracts/build/contracts/SmartIdentity.json');
const DeviceContractRegistryArtifact = require('./smartId-contracts/build/contracts/DeviceContractRegistry.json');

const SmartIdentity = new web3.eth.Contract(
    SmartIdentityArtifact.abi, 
    '0xBb7c80D58101b9a1785624CC1BF685D9d1d0fc01'
);

const DeviceContractRegistry = new web3.eth.Contract(
    DeviceContractRegistryArtifact.abi, 
    '0xcCe65De1e6815903d3BD047cB05a8780E6deA904'
);

const app = express();

app.use(express.static('frontend')); // This line serves all static files from the frontend directory

// Example of serving login.html
app.get('/login.html', (req, res) => {
  console.log('Serving login.html');
    res.sendFile(path.join(__dirname, 'frontend', 'views', 'login.html'));
});

app.get('/register.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', 'views', 'register.html'));
});

// Serve feedback form
app.get('/feedback', (req, res) => {
  res.sendFile(path.join(__dirname,'frontend', 'views', 'feedback.html'));
});



// Enable CORS for all routes
app.use(cors({
  origin: [
    'http://127.0.0.1:5500',
    'http://localhost:5500',
    'http://127.0.0.1:3000',
    'http://localhost:3000',
    'http://127.0.0.1:3001',  // Your actual server port
    'http://localhost:3001',   // Your actual server port
    'null' // For file:// protocols during development
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// 2. Body parsing middleware AFTER CORS
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 3. Add explicit OPTIONS handler for preflight requests
app.options('*', cors()); // This is important!


// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB Connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// Define Mongoose Schemas
//User -> Service Requester and Provider

// Define Mongoose Schemas
const ServiceOfferedSchema = new mongoose.Schema({
  name: String,
  description: String,
  is_active: Boolean
});

const FeedbackSchema = new mongoose.Schema({
  service_id: mongoose.Schema.Types.ObjectId,
  provider_id: mongoose.Schema.Types.ObjectId,
  requester_id: mongoose.Schema.Types.ObjectId,
  rating: Number, // Overall rating for backward compatibility
  comment: String,
  
  // NEW: Feedback direction indicator
  feedback_type: {
    type: String,
    enum: ['requester_to_provider', 'provider_to_requester'],
    required: true
  },
  
  // FOR REQUESTER-TO-PROVIDER FEEDBACK (existing)
  availability: { 
    type: Number, 
    min: 1, 
    max: 5, 
    required: function() { return this.feedback_type === 'requester_to_provider'; }
  },
  avoidance: { 
    type: Number, 
    min: 1, 
    max: 5, 
    required: function() { return this.feedback_type === 'requester_to_provider'; }
  },
  communication: { 
    type: Number, 
    min: 1, 
    max: 5, 
    required: true // Required for both types but different meanings
  },
  credibility: { 
    type: Number, 
    min: 1, 
    max: 5, 
    required: function() { return this.feedback_type === 'requester_to_provider'; }
  },
  reliability: { 
    type: Number, 
    min: 1, 
    max: 5, 
    required: true // Required for both types but different meanings
  },
  
  // FOR PROVIDER-TO-REQUESTER FEEDBACK (new)
  payment: { 
    type: Number, 
    min: 1, 
    max: 5, 
    required: function() { return this.feedback_type === 'provider_to_requester'; }
  }, // Payment: on-time, full amount, no chargebacks
  
  fairness: { 
    type: Number, 
    min: 1, 
    max: 5, 
    required: function() { return this.feedback_type === 'provider_to_requester'; }
  }, // Fairness: reasonable demands, respectful tone
  
  clarity: { 
    type: Number, 
    min: 1, 
    max: 5, 
    required: function() { return this.feedback_type === 'provider_to_requester'; }
  }, // Clarity: unambiguous task definitions, timely updates
  
  created_at: {
    type: Date,
    default: Date.now
  }
});

const ServiceAvailedSchema = new mongoose.Schema({
  service_id: mongoose.Schema.Types.ObjectId,
  name: String,
  description: String,
  provider_id: mongoose.Schema.Types.ObjectId
});

// UPDATED USER SCHEMA - Enhanced to support bidirectional feedback
const UserSchema = new mongoose.Schema({
  owner_address: {
      type: String,
      required: true,
      unique: true
  },
  password: {
      type: String,
      required: true
  },
  ip_address: {
      type: String,
      required: true
  },
  role: {
      type: String,
      enum: ['requester', 'provider'],
      required: true,
      default: 'requester'
  },
  device_info: {
    ipAddress: String,
    imei: String,
    macAddress: String
  },
  
  // Fields specific to providers
  services_offered: {
      type: [ServiceOfferedSchema],
      required: function () { return this.role === 'provider'; },
      default: undefined
  },

  // Fields specific to providers
  services_offered: {
      type: [ServiceOfferedSchema],
      required: function () { return this.role === 'provider'; },
      default: undefined
  },


// ENHANCED TRUST REPUTATION - Now supports both roles
trust_reputation: {
  type: {
    overall_score: { type: Number, default: 100 },
    parameter_scores: {
      // For PROVIDERS (rated by requesters)
      availability: { type: Number, default: 5 },
      avoidance: { type: Number, default: 5 },
      communication: { type: Number, default: 5 },
      credibility: { type: Number, default: 5 },
      reliability: { type: Number, default: 5 },
      
      // For REQUESTERS (rated by providers) 
      payment: { type: Number, default: 5 },
      fairness: { type: Number, default: 5 },
      clarity: { type: Number, default: 5 }
      // communication and reliability are shared
    },
    category: { type: String, enum: ['white', 'grey', 'black'], default: 'white' },
    total_feedback_count: { type: Number, default: 0 },
    last_calculated: { type: Date, default: Date.now }
  },
  default: function() {
    if (this.role === 'provider') {
      return { 
        overall_score: 100, 
        parameter_scores: {
          availability: 5,
          avoidance: 5,
          communication: 5,
          credibility: 5,
          reliability: 5
        },
        category: 'white',
        total_feedback_count: 0,
        last_calculated: new Date()
      };
    } else {
      // Requester default scores
      return { 
        overall_score: 100, 
        parameter_scores: {
          payment: 5,
          communication: 5,
          fairness: 5,
          clarity: 5,
          reliability: 5
        },
        category: 'white',
        total_feedback_count: 0,
        last_calculated: new Date()
      };
    }
  }
},

banned_details: {
  type: {
      is_banned: {
          type: Boolean,
          default: false
      },
      is_permanent: {
          type: Boolean,
          default: false
      },
      banned_until: {
          type: Date,
          default: null
      },
      reason: {
          type: String,
          default: ''
      }
  },
  default: {}
},

// Fields for requesters
services_availed: {
  type: [ServiceAvailedSchema],
  required: function () { return this.role === 'requester'; },
  default: undefined
},

// BIDIRECTIONAL feedback storage
feedback_received: {
  type: [FeedbackSchema],
  default: []
},

feedback_given: {
  type: [FeedbackSchema],
  default: []
},

// NEW: Track services provided (for providers to rate requesters)
services_provided: {
  type: [{
    service_id: mongoose.Schema.Types.ObjectId,
    requester_id: mongoose.Schema.Types.ObjectId,
    requester_address: String,
    service_name: String,
    provided_at: { type: Date, default: Date.now },
    feedback_given: { type: Boolean, default: false }
  }],
  required: function () { return this.role === 'provider'; },
  default: []
},

created_at: {
    type: Date,
    default: Date.now
}
});


// Pre-save hook to hash password before saving
UserSchema.pre('save', async function (next) {
  if (this.isModified('password') || this.isNew) {
    const hash = await bcrypt.hash(this.password, 12);
    this.password = hash;
  }
  next();
});

// Method to compare submitted passwords with hashed password
UserSchema.methods.comparePassword = function(candidatePassword, callback) {
  bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
    if (err) return callback(err);
    callback(null, isMatch);
  });
};

const User = mongoose.model('User', UserSchema);
const Feedback = mongoose.model('Feedback', FeedbackSchema);

module.exports = User;


// Dependencies needed for authentication
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

// Apply a rate limiter to login attempts to prevent brute force attacks
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // max requests per windowMs
  message: { message: "Too many login attempts from this IP, please try again after 15 minutes" }
});

// Middleware to extract IP address
const getIpAddress = (req, res, next) => {
  const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  req.ipAddress = ip;
  next();
};


//Blockchain
// Device Management Functions

async function addDevice(ipAddress, imei, macAddress) {
  const accounts = await web3.eth.getAccounts();
  const ipHash = web3.utils.keccak256(ipAddress);
  const imeiHash = web3.utils.keccak256(imei);
  const macHash = web3.utils.keccak256(macAddress);

  try {
      await SmartIdentity.methods.registerDevice(ipHash, imeiHash, macHash).send({ from: accounts[0] });
      console.log('Device added to blockchain:', imeiHash);
      return imeiHash;
  } catch (error) {
      console.error('Error adding device to blockchain:', error.message);
      throw new Error('Failed to add device');
  }
}


async function isDeviceBlacklisted(ipAddress, imei, macAddress) {
  const ipHash = web3.utils.keccak256(ipAddress);
  const imeiHash = web3.utils.keccak256(imei);
  const macHash = web3.utils.keccak256(macAddress);

  try {
      // Calling the updated function to check the blacklist status
      const deviceDetails = await SmartIdentity.methods.getDeviceDetails(imeiHash).call();
      
      // Check if the device exists (i.e., deviceDetails have non-empty values)
      if (deviceDetails[1] === "0x0000000000000000000000000000000000000000000000000000000000000000") {
          console.error('Device not found on the blockchain');
          throw new Error('Device not found on the blockchain');
      }

      console.log('Device blacklist status:', deviceDetails[3]);
      return deviceDetails[3]; // Returning the `isBlacklisted` status from the device details
  } catch (error) {
      console.error('Error checking blacklist status on blockchain:', error.message);
      throw new Error('Failed to check blacklist status');
  }
}


async function blacklistDevice(imei) {
  const accounts = await web3.eth.getAccounts();
  const imeiHash = web3.utils.keccak256(imei);

  try {
      // Check if the device exists before attempting to blacklist
      const deviceDetails = await SmartIdentity.methods.getDeviceDetails(imeiHash).call();
      
      if (deviceDetails[1] === "0x0000000000000000000000000000000000000000000000000000000000000000") {
          console.error('Device not found on the blockchain');
          throw new Error('Device not found');
      }

      // Attempt to blacklist the device
      await SmartIdentity.methods.blacklistDevice(imeiHash).send({ from: accounts[0], gas: 8000000 });
      console.log('Device blacklisted:', imeiHash);
      return imeiHash;
  } catch (error) {
      console.error('Error blacklisting device on blockchain:', error.message);
      throw new Error('Failed to blacklist device');
  }
}



// Device-related API Endpoints

app.post('/api/device/add-device', async (req, res) => {
  const { ipAddress, imei, macAddress } = req.body;

  try {
      const deviceHash = await addDevice(ipAddress, imei, macAddress);
      res.status(200).json({ message: 'Device added', hash: deviceHash });
  } catch (error) {
      res.status(500).json({ error: error.message });
  }
});


app.get('/api/device/check-blacklist', async (req, res) => {
  const { ipAddress, imei, macAddress } = req.query;

  try {
      const isBlacklisted = await isDeviceBlacklisted(ipAddress, imei, macAddress);
      res.status(200).json({ blacklisted: isBlacklisted });
  } catch (error) {
      res.status(500).json({ error: error.message });
  }
});


// Blacklist Device Endpoint
app.post('/api/device/blacklist-device', async (req, res) => {
  const { imei } = req.body;

  try {
      const deviceHash = await blacklistDevice(imei);
      res.status(200).json({ message: 'Device blacklisted', hash: deviceHash });
  } catch (error) {
      res.status(500).json({ error: error.message });
  }
});



//Defining API Endpoints

// Fixed Register a New User (Service Provider or Requester)
app.post('/users/register', getIpAddress, async (req, res) => {
  console.log('Request received for registration:', req.body);
  const { owner_address, password, role } = req.body;

  // Check if the IP is blacklisted
  const isBlacklisted = await User.findOne({
      'ip_address': req.ipAddress,
      'banned_details.is_banned': true
  });

  if (isBlacklisted) {
      return res.status(403).json({ message: "Your IP is blacklisted. You cannot register." });
  }

  let availableDevice = null; // Declare outside try block for cleanup

  try {
      const existingUser = await User.findOne({ owner_address });
      if (existingUser) {
          return res.status(409).json({ message: "User already exists." });
      }

      // Assign an unassigned device identifier
      availableDevice = deviceIdentifiers.find(device => device.assigned === false);
      if (!availableDevice) {
          return res.status(500).json({ message: "No available device identifiers." });
      }

      // Check if device is already registered on blockchain before attempting to register
      console.log('Checking if device already exists on blockchain...');
      try {
          const imeiHash = web3.utils.keccak256(availableDevice.imei);
          const deviceDetails = await SmartIdentity.methods.getDeviceDetails(imeiHash).call();
          
          // If device details exist (not all zeros), device is already registered
          if (deviceDetails[1] !== "0x0000000000000000000000000000000000000000000000000000000000000000") {
              console.log('Device already exists on blockchain, skipping registration');
          } else {
              // Device doesn't exist, register it
              console.log('Device not found on blockchain, registering...');
              await addDevice(availableDevice.ipAddress, availableDevice.imei, availableDevice.macAddress);
              console.log('Device successfully registered on blockchain');
          }
      } catch (blockchainError) {
          // If it's not a "device already registered" error, then it's a real problem
          if (!blockchainError.message.includes('Device already registered') && 
              !blockchainError.message.includes('revert Device already registered')) {
              console.error('Error with blockchain operation:', blockchainError);
              return res.status(500).json({ 
                  message: 'Failed to interact with blockchain. Registration aborted.', 
                  error: blockchainError.message 
              });
          } else {
              console.log('Device already registered on blockchain, continuing with user registration');
          }
      }

      // Mark device as assigned AFTER blockchain check/registration
      availableDevice.assigned = true;
      fs.writeFileSync(path.resolve(__dirname, 'device_identifiers.json'), JSON.stringify(deviceIdentifiers, null, 2));
      console.log('Device marked as assigned in local file');

      const newUser = new User({
          owner_address,
          password,
          role,
          ip_address: req.ipAddress,
          device_info: availableDevice, // Store the assigned device info
      });

      if (role === 'provider') {
          newUser.services_offered = [];
          newUser.trust_reputation = {
              overall_score: 100,
              parameter_scores: {
                  availability: 5,
                  avoidance: 5,
                  communication: 5,
                  credibility: 5,
                  reliability: 5
              },
              category: 'white',
              total_feedback_count: 0,
              last_calculated: new Date()
          };
          newUser.banned_details = {
              is_banned: false,
              is_permanent: false,
              banned_until: null,
              reason: ''
          };
          newUser.feedback_received = []; // Initialize feedback array
      } else if (role === 'requester') {
          newUser.services_availed = [];
          newUser.feedback_given = []; // Initialize feedback array
          newUser.trust_reputation = {
              overall_score: 100,
              parameter_scores: {
                  availability: 5,
                  avoidance: 5,
                  communication: 5,
                  credibility: 5,
                  reliability: 5
              },
              category: 'white',
              total_feedback_count: 0,
              last_calculated: new Date()
          };
      }

      // Save the new user to the database
      console.log('Saving user to database...');
      const savedUser = await newUser.save();
      console.log('User successfully saved to database:', savedUser.owner_address);
      
      // Send success response
      res.status(201).json({
          message: 'User registered successfully',
          user: {
              id: savedUser._id,
              owner_address: savedUser.owner_address,
              role: savedUser.role,
              created_at: savedUser.created_at
          }
      });

  } catch (error) {
      console.error('Registration error:', error);
      
      // ROLLBACK: If we've marked a device as assigned but failed to save user, unmark it
      if (availableDevice && availableDevice.assigned === true) {
          console.log('Rolling back device assignment due to error...');
          availableDevice.assigned = false;
          try {
              fs.writeFileSync(path.resolve(__dirname, 'device_identifiers.json'), JSON.stringify(deviceIdentifiers, null, 2));
              console.log('Device assignment rolled back successfully');
          } catch (rollbackError) {
              console.error('Error during rollback:', rollbackError);
          }
      }
      
      res.status(500).json({ message: error.message });
  }
});



//Login API Endpoint
// Login API Endpoint
app.post('/users/login', getIpAddress, loginLimiter, async (req, res) => {
  console.log('Login attempt received');
  console.log('Request body:', req.body);

  const { owner_address, password } = req.body;
  console.log(`Attempting login for owner_address: ${owner_address}`);

  try {
      // Check if the IP is blacklisted
      console.log(`Checking if IP ${req.ipAddress} is blacklisted`);
      const isBlacklisted = await User.findOne({ ip_address: req.ipAddress, 'banned_details.is_banned': true });
      
      // Check if user exists
      console.log(`Looking for user with owner_address: ${owner_address}`);
      const user = await User.findOne({ owner_address });
      if (!user) {
          console.log(`No user found with owner_address: ${owner_address}`);
          return res.status(401).json({ message: "User not found." });
      } else {
          console.log(`User found: ${user.owner_address}`);
      }

      // Check if the device is blacklisted on the blockchain
      console.log('Checking if device is blacklisted on the blockchain');
      const isBlacklistedBlockchain = await isDeviceBlacklisted(user.device_info.ipAddress, user.device_info.imei, user.device_info.macAddress);
      if (isBlacklisted || isBlacklistedBlockchain) {
          return res.status(403).json({ message: "Your IP is blacklisted. You cannot login." });
      }

      // Check if the password is correct
      console.log('Comparing passwords');
      console.log('Password received:', password);
      console.log('Hashed password from DB:', user.password);
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
          console.log('Password does not match');
          return res.status(401).json({ message: "Incorrect password." });
      } else {
          console.log('Password matches');
      }

      // If password matches, proceed to generate the token
      console.log('Signing JWT token');
      // Generate JWT token when user logs in
      const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });

      console.log('JWT token signed:', token);
      
      // Send the response back with token, id, and role
      console.log('Sending response:', { token, id: user._id, role: user.role });
      res.status(200).json({ 
          token: token,
          id: user._id,
          role: user.role 
      });

  } catch (error) {
      console.error('Error during login process:', error);
      res.status(500).json({ message: "Server error during login.", error });
  }
});




// Token verification middleware
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ message: 'No token provided.' });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: 'Failed to authenticate token.' });
    req.userId = decoded.id;  // Store the decoded id in req.userId for use in the route
    next();
  });
};

// Use verifyToken as middleware
app.get('/protected-route', verifyToken, (req, res) => {
  res.send('This is a protected route');
});



// Retrieve User Details
app.get('/users/:id', async (req, res) => {
  try {
      const user = await User.findById(req.params.id);
      if (!user) {
          return res.status(404).json({ message: 'User not found' });
      }
      res.status(200).json(user);
  } catch (error) {
      res.status(500).json({ message: 'Error retrieving user data', error });
  }
});


// Add a New Service (Provider Only)
app.put('/users/:id/services', async (req, res) => {
  const { service } = req.body;
  try {
      const updatedUser = await User.findByIdAndUpdate(
          req.params.id,
          { $push: { services_offered: service } },
          { new: true, runValidators: true }
      );
      if (!updatedUser) {
          return res.status(404).json({ message: 'User not found' });
      }
      res.status(200).json(updatedUser);
  } catch (error) {
      res.status(500).json({ message: 'Error adding new service', error });
  }
});

// Remove a Service from a User (Service Provider)
app.delete('/users/:id/services/:service_id', async (req, res) => {
  try {
    const updatedUser = await User.findByIdAndUpdate(
      req.params.id,
      { $pull: { services_offered: { _id: req.params.service_id } } },
      { new: true }
    );
    if (!updatedUser) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.status(200).json(updatedUser);
  } catch (error) {
    res.status(500).json({ message: 'Error removing service', error });
  }
});

// List All Active Services
app.get('/services', async (req, res) => {
  try {
      const providers = await User.find({ role: 'provider', 'services_offered': { $exists: true, $ne: [] } });
      //This query fetches all providers with non-empty services_offered arrays.
      const activeServices = providers.map(provider => provider.services_offered).flat();
      res.status(200).json(activeServices);
  } catch (error) {
      res.status(500).json({ message: 'Error retrieving services', error });
  }
});


// UPDATED AVAIL SERVICE ENDPOINT - Replace in app.js

app.post('/users/:id/avail-service', async (req, res) => {
  const { serviceId } = req.body;
  const userId = req.params.id;

  try {
      // Find the service in the database
      const serviceProvider = await User.findOne({ 'services_offered._id': serviceId, role: 'provider' });
      if (!serviceProvider) {
          return res.status(404).json({ message: 'Service not found' });
      }

      // Find the requester
      const requester = await User.findById(userId);
      if (!requester || requester.role !== 'requester') {
          return res.status(404).json({ message: 'Requester not found' });
      }

      const service = serviceProvider.services_offered.id(serviceId);

      const availedService = {
        service_id: service._id,
        name: service.name,
        description: service.description,
        provider_id: serviceProvider._id // Add provider info manually
      };

      // Update the requester's availed services
      await User.findByIdAndUpdate(
          userId,
          { $push: { services_availed: availedService } },
          { new: true, runValidators: true }
      );

      // NEW: Track this service in provider's services_provided array
      const serviceProvided = {
        service_id: service._id,
        requester_id: requester._id,
        requester_address: requester.owner_address,
        service_name: service.name,
        provided_at: new Date(),
        feedback_given: false
      };

      // Initialize services_provided if not present
      if (!serviceProvider.services_provided) {
        serviceProvider.services_provided = [];
      }

      serviceProvider.services_provided.push(serviceProvided);
      await serviceProvider.save();

      console.log('Service availed and tracked successfully');
      res.status(200).json({ 
        message: 'Service availed successfully',
        service: availedService
      });

  } catch (error) {
      console.error('Error availing service:', error);
      res.status(500).json({ message: 'Error availing service', error });
  }
});


// Retrieve Details of a Specific Service
app.get('/services/:serviceId', async (req, res) => {
  try {
    const serviceId = req.params.serviceId;
    const provider = await User.findOne({ 'services_offered._id': serviceId, role: 'provider' });
    
    if (!provider) {
      return res.status(404).json({ message: 'Service not found' });
    }

    const service = provider.services_offered.id(serviceId);
    res.status(200).json(service);
  } catch (error) {
    res.status(500).json({ message: 'Error retrieving service details', error });
  }
});

// UPDATED SUBMIT FEEDBACK ENDPOINT - Replace the existing one in app.js

app.post('/submit-feedback', async (req, res) => {
  const { 
    requester_id, 
    service_id, 
    provider_id,
    feedback_type,
    rating, // Keep for backward compatibility
    comment,
    // Requester-to-Provider parameters (existing)
    availability,
    avoidance,
    communication,
    credibility,
    reliability,
    // Provider-to-Requester parameters (new)
    payment,
    fairness,
    clarity
  } = req.body;

  try {
    // Determine feedback direction
    let feedbackType = feedback_type;
    if (!feedbackType) {
      // For backward compatibility - if not specified, assume requester-to-provider
      feedbackType = 'requester_to_provider';
    }

    console.log('Processing feedback of type:', feedbackType);

    // Validate required parameters based on feedback type
    if (feedbackType === 'requester_to_provider') {
      // Validate requester-to-provider parameters
      if (!availability || !avoidance || !communication || !credibility || !reliability) {
        return res.status(400).json({ 
          message: 'All trust parameters (availability, avoidance, communication, credibility, reliability) are required for requester feedback' 
        });
      }

      const parameters = { availability, avoidance, communication, credibility, reliability };
      for (const [key, value] of Object.entries(parameters)) {
        if (value < 1 || value > 5) {
          return res.status(400).json({ 
            message: `${key} must be between 1 and 5` 
          });
        }
      }
    } else if (feedbackType === 'provider_to_requester') {
      // Validate provider-to-requester parameters
      if (!payment || !communication || !fairness || !clarity || !reliability) {
        return res.status(400).json({ 
          message: 'All parameters (payment, communication, fairness, clarity, reliability) are required for provider feedback' 
        });
      }

      const parameters = { payment, communication, fairness, clarity, reliability };
      for (const [key, value] of Object.entries(parameters)) {
        if (value < 1 || value > 5) {
          return res.status(400).json({ 
            message: `${key} must be between 1 and 5` 
          });
        }
      }
    }

    // Find the service provider and requester
    const serviceProvider = await User.findById(provider_id);
    const requester = await User.findById(requester_id);
    
    if (!serviceProvider || serviceProvider.role !== 'provider') {
      return res.status(404).json({ message: 'Service provider not found' });
    }
    
    if (!requester || requester.role !== 'requester') {
      return res.status(404).json({ message: 'Requester not found' });
    }

    // Check if the feedback giver is banned
    if (feedbackType === 'requester_to_provider') {
      if (requester.banned_details && requester.banned_details.is_banned) {
        const bannedUntil = new Date(requester.banned_details.banned_until);
        if (bannedUntil > new Date()) {
          return res.status(403).json({ 
            message: `You are temporarily banned from submitting feedback until ${bannedUntil.toDateString()}. Reason: ${requester.banned_details.reason}` 
          });
        }
      }
    } else {
      if (serviceProvider.banned_details && serviceProvider.banned_details.is_banned) {
        const bannedUntil = new Date(serviceProvider.banned_details.banned_until);
        if (bannedUntil > new Date()) {
          return res.status(403).json({ 
            message: `You are temporarily banned from submitting feedback until ${bannedUntil.toDateString()}. Reason: ${serviceProvider.banned_details.reason}` 
          });
        }
      }
    }

    // Create the feedback object based on type
    let feedback;
    
    if (feedbackType === 'requester_to_provider') {
      // Calculate overall rating for backward compatibility
      const overallRating = Math.round((availability + avoidance + communication + credibility + reliability) / 5);
      
      feedback = {
        service_id,
        provider_id,
        requester_id,
        feedback_type: feedbackType,
        rating: overallRating,
        comment,
        availability,
        avoidance,
        communication,
        credibility,
        reliability,
        created_at: new Date()
      };
    } else {
      // Provider-to-requester feedback
      const overallRating = Math.round((payment + communication + fairness + clarity + reliability) / 5);
      
      feedback = {
        service_id,
        provider_id,
        requester_id,
        feedback_type: feedbackType,
        rating: overallRating,
        comment,
        payment,
        communication,
        fairness,
        clarity,
        reliability,
        created_at: new Date()
      };
    }

    // Initialize feedback arrays if not present
    if (!serviceProvider.feedback_received) serviceProvider.feedback_received = [];
    if (!serviceProvider.feedback_given) serviceProvider.feedback_given = [];
    if (!requester.feedback_received) requester.feedback_received = [];
    if (!requester.feedback_given) requester.feedback_given = [];

    // Add feedback to appropriate arrays based on direction
    if (feedbackType === 'requester_to_provider') {
      // Requester rating provider
      serviceProvider.feedback_received.push(feedback);
      requester.feedback_given.push(feedback);
      
      // Calculate new trust reputation for the provider
      console.log('Calculating provider reputation...');
      const updatedProviderReputation = calculateProviderReputation(serviceProvider.feedback_received);
      serviceProvider.trust_reputation = updatedProviderReputation;
      updateBanStatus(serviceProvider);
      
      await serviceProvider.save();
      await requester.save();
      
      res.status(200).json({ 
        message: "Provider feedback submitted successfully.",
        provider_reputation: updatedProviderReputation
      });
      
    } else {
      // Provider rating requester
      requester.feedback_received.push(feedback);
      serviceProvider.feedback_given.push(feedback);
      
      // Calculate new trust reputation for the requester
      console.log('Calculating requester reputation...');
      const updatedRequesterReputation = calculateRequesterReputation(requester.feedback_received);
      requester.trust_reputation = updatedRequesterReputation;
      updateRequesterBanStatus(requester);
      
      await serviceProvider.save();
      await requester.save();
      
      res.status(200).json({ 
        message: "Requester feedback submitted successfully.",
        requester_reputation: updatedRequesterReputation
      });
    }

  } catch (error) {
    console.error('Error handling feedback:', error);
    res.status(500).json({ message: "Error submitting feedback.", error: error.message });
  }
});

// NEW: Calculate requester reputation based on provider feedback
function calculateRequesterReputation(feedbackArray) {
  console.log('Calculating requester reputation from feedback array:', feedbackArray);
  
  // Filter for provider-to-requester feedback only
  const relevantFeedback = feedbackArray.filter(f => f.feedback_type === 'provider_to_requester');
  
  if (!relevantFeedback || relevantFeedback.length === 0) {
    return {
      overall_score: 100, // Default high score for new requesters
      parameter_scores: {
        payment: 5,
        communication: 5,
        fairness: 5,
        clarity: 5,
        reliability: 5
      },
      category: 'white',
      total_feedback_count: 0,
      last_calculated: new Date()
    };
  }

  const totalFeedback = relevantFeedback.length;
  
  // Calculate average scores for each parameter
  const parameterTotals = {
    payment: 0,
    communication: 0,
    fairness: 0,
    clarity: 0,
    reliability: 0
  };

  relevantFeedback.forEach(feedback => {
    parameterTotals.payment += feedback.payment || 0;
    parameterTotals.communication += feedback.communication || 0;
    parameterTotals.fairness += feedback.fairness || 0;
    parameterTotals.clarity += feedback.clarity || 0;
    parameterTotals.reliability += feedback.reliability || 0;
  });

  const parameterAverages = {
    payment: parameterTotals.payment / totalFeedback,
    communication: parameterTotals.communication / totalFeedback,
    fairness: parameterTotals.fairness / totalFeedback,
    clarity: parameterTotals.clarity / totalFeedback,
    reliability: parameterTotals.reliability / totalFeedback
  };

  console.log('Requester parameter averages:', parameterAverages);

  // Calculate overall score using weights
  const weights = {
    payment: 0.2,        // 20%
    communication: 0.2,  // 20%
    fairness: 0.2,       // 20%
    clarity: 0.2,        // 20%
    reliability: 0.2     // 20%
  };

  const weightedScore = (
    parameterAverages.payment * weights.payment +
    parameterAverages.communication * weights.communication +
    parameterAverages.fairness * weights.fairness +
    parameterAverages.clarity * weights.clarity +
    parameterAverages.reliability * weights.reliability
  );

  // Convert to 0-100 scale
  const overallScore = (weightedScore / 5) * 100;

  console.log('Requester weighted score:', weightedScore, 'Overall score:', overallScore);

  // Determine category
  let category;
  if (overallScore >= 70) {
    category = 'white';
  } else if (overallScore >= 40) {
    category = 'grey';
  } else {
    category = 'black';
  }

  const reputation = {
    overall_score: Math.round(overallScore * 100) / 100,
    parameter_scores: {
      payment: Math.round(parameterAverages.payment * 100) / 100,
      communication: Math.round(parameterAverages.communication * 100) / 100,
      fairness: Math.round(parameterAverages.fairness * 100) / 100,
      clarity: Math.round(parameterAverages.clarity * 100) / 100,
      reliability: Math.round(parameterAverages.reliability * 100) / 100
    },
    category,
    total_feedback_count: totalFeedback,
    last_calculated: new Date()
  };

  console.log('Final requester reputation:', reputation);
  return reputation;
}


// Update Provider Ban Status based on their reputation
function updateBanStatus(serviceProvider) {
  if (!serviceProvider.trust_reputation) {
    console.log('No trust reputation found for provider');
    return;
  }
  const score = serviceProvider.trust_reputation.overall_score;
  
  // Initialize banned_details if not present
  if (!serviceProvider.banned_details) {
    serviceProvider.banned_details = {};
  }
  
  console.log('Updating provider ban status. Score:', score);
  
  if (score >= 70) {
    // White category - ensure not banned
    serviceProvider.banned_details.is_banned = false;
    serviceProvider.banned_details.is_permanent = false;
    serviceProvider.banned_details.banned_until = null;
    serviceProvider.banned_details.reason = '';
    console.log('Provider set to not banned (white category)');
  } else if (score < 30) {
    // Black category - ban the provider
    serviceProvider.banned_details.is_banned = true;
    serviceProvider.banned_details.is_permanent = false;
    serviceProvider.banned_details.banned_until = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
    serviceProvider.banned_details.reason = 'Low trust reputation score';
    console.log('Provider banned (black category)');
  } else {
    // Grey category (30-70) - no automatic ban, but monitored
    console.log('Provider in grey category - monitored but not banned');
  }
}

// Update Requester Ban Status based on their reputation  
function updateRequesterBanStatus(requester) {
  if (!requester.trust_reputation) {
    console.log('No trust reputation found for requester');
    return;
  }
  const score = requester.trust_reputation.overall_score;
  
  // Initialize banned_details if not present
  if (!requester.banned_details) {
    requester.banned_details = {};
  }
  
  console.log('Updating requester ban status. Score:', score);
  
  if (score >= 70) {
    // White category - ensure not banned
    requester.banned_details.is_banned = false;
    requester.banned_details.is_permanent = false;
    requester.banned_details.banned_until = null;
    requester.banned_details.reason = '';
    console.log('Requester set to not banned (white category)');
  } else if (score < 30) {
    // Black category - ban the requester
    requester.banned_details.is_banned = true;
    requester.banned_details.is_permanent = false;
    requester.banned_details.banned_until = new Date(Date.now() + 15 * 24 * 60 * 60 * 1000); // 15 days for requesters
    requester.banned_details.reason = 'Low trust reputation score';
    console.log('Requester banned (black category)');
  } else {
    // Grey category (30-70) - no automatic ban, but monitored
    console.log('Requester in grey category - monitored but not banned');
  }
}

// KEEP the existing calculateProviderReputation function (unchanged)
function calculateProviderReputation(feedbackArray) {
  console.log('Calculating provider reputation from feedback array:', feedbackArray);
  
  // Filter for requester-to-provider feedback only
  const relevantFeedback = feedbackArray.filter(f => !f.feedback_type || f.feedback_type === 'requester_to_provider');
  
  if (!relevantFeedback || relevantFeedback.length === 0) {
    return {
      overall_score: 0,
      parameter_scores: {
        availability: 0,
        avoidance: 0,
        communication: 0,
        credibility: 0,
        reliability: 0
      },
      category: 'white',
      total_feedback_count: 0,
      last_calculated: new Date()
    };
  }

  const totalFeedback = relevantFeedback.length;
  
  // Calculate average scores for each parameter
  const parameterTotals = {
    availability: 0,
    avoidance: 0,
    communication: 0,
    credibility: 0,
    reliability: 0
  };

  relevantFeedback.forEach(feedback => {
    parameterTotals.availability += feedback.availability || 0;
    parameterTotals.avoidance += feedback.avoidance || 0;
    parameterTotals.communication += feedback.communication || 0;
    parameterTotals.credibility += feedback.credibility || 0;
    parameterTotals.reliability += feedback.reliability || 0;
  });

  const parameterAverages = {
    availability: parameterTotals.availability / totalFeedback,
    avoidance: parameterTotals.avoidance / totalFeedback,
    communication: parameterTotals.communication / totalFeedback,
    credibility: parameterTotals.credibility / totalFeedback,
    reliability: parameterTotals.reliability / totalFeedback
  };

  console.log('Provider parameter averages:', parameterAverages);

  // Calculate overall score (weighted average)
  const weights = {
    availability: 0.2,    // 20%
    avoidance: 0.2,      // 20%
    communication: 0.2,   // 20%
    credibility: 0.2,     // 20%
    reliability: 0.2      // 20%
  };

  const weightedScore = (
    parameterAverages.availability * weights.availability +
    parameterAverages.avoidance * weights.avoidance +
    parameterAverages.communication * weights.communication +
    parameterAverages.credibility * weights.credibility +
    parameterAverages.reliability * weights.reliability
  );

  // Convert to 0-100 scale
  const overallScore = (weightedScore / 5) * 100;

  console.log('Provider weighted score:', weightedScore, 'Overall score:', overallScore);

  // Determine category
  let category;
  if (overallScore >= 70) {
    category = 'white';
  } else if (overallScore >= 40) {
    category = 'grey';
  } else {
    category = 'black';
  }

  const reputation = {
    overall_score: Math.round(overallScore * 100) / 100,
    parameter_scores: {
      availability: Math.round(parameterAverages.availability * 100) / 100,
      avoidance: Math.round(parameterAverages.avoidance * 100) / 100,
      communication: Math.round(parameterAverages.communication * 100) / 100,
      credibility: Math.round(parameterAverages.credibility * 100) / 100,
      reliability: Math.round(parameterAverages.reliability * 100) / 100
    },
    category,
    total_feedback_count: totalFeedback,
    last_calculated: new Date()
  };

  console.log('Final provider reputation:', reputation);
  return reputation;
}


// API Endpoint to check ban status of a User
app.get('/check-ban/:userId', async (req, res) => {
  try {
    const user = await User.findById(req.params.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.status(200).json({ banned_status: user.banned_details });
  } catch (error) {
    res.status(500).json({ message: 'Error checking ban status', error });
  }
});

// API Endpoint to update the banned status of a User
app.put('/update-ban/:userId', async (req, res) => {
  const { is_banned, is_permanent, banned_until, reason } = req.body;
  try {
    const updatedUser = await User.findByIdAndUpdate(
      req.params.userId,
      {
        'banned_details.is_banned': is_banned, 
        'banned_details.is_permanent': is_permanent, 
        'banned_details.banned_until': banned_until, 
        'banned_details.reason': reason
      },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.status(200).json(updatedUser);
  } catch (error) {
    res.status(500).json({ message: 'Error updating ban status', error });
  }
});

// Retrieve the Trust Reputation of a User (Service Provider)
app.get('/users/:id/trust_reputation', async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.status(200).json({ trust_reputation: user.trust_reputation });
  } catch (error) {
    res.status(500).json({ message: 'Error retrieving trust reputation', error });
  }
});




            // Trust and Reputation Management Endpoints
// Calculate the global trust and reputation for a service provider
app.post('/reputation/calculate/:userId', async (req, res) => {
    try {
      const userId = req.params.userId;
      const user = await User.findById(userId);
      
      // Check if the user is a service provider
      if (!user || user.role !== 'provider') {
        return res.status(404).json({ message: 'Service Provider not found or user is not a provider' });
      }
      
      // Fetch all feedback for the specific service provider
      const feedbackList = await Feedback.find({ user_id: userId });
  
      // Assuming 'calculateLocalTrust' is a function that calculates local trust for each feedback
      const localTrustValues = feedbackList.map(feedback => calculateLocalTrust(feedback));
  
      // Calculate global trust as the weighted sum of all local trust values
      const globalTrust = calculateGlobalTrust(localTrustValues);
  
      // Derive the reputation from the global trust value
      const reputation = deriveReputationFromGlobalTrust(globalTrust);
  
      // Determine the category based on the reputation score
      const category = categorizeReputation(reputation);

      // Update the service provider's trust reputation in the database
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { 'trust_reputation.score': reputation, 'trust_reputation.category': category },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ message: 'Service Provider not found' });
    }

    res.status(200).json({ trust_reputation: updatedUser.trust_reputation });
  } catch (error) {
    res.status(500).json({ message: 'Error calculating reputation', error });
  }
});
  

// Placeholder function for local trust calculation based on feedback parameters
function calculateLocalTrust(feedbackParams) {
    // Assuming a simple average of provided feedback parameters for demonstration purposes
    const { A, Av, C, Cr, R } = feedbackParams;
    const sumOfParameters = A + Av + C + Cr + R;
    const numberOfParameters = 5; // Total number of parameters we're considering
    const localTrust = sumOfParameters / numberOfParameters;
    return localTrust;
  }
  
  // Function to calculate global trust as a weighted sum of local trust values
  function calculateGlobalTrust(feedbackList) {
    // Assuming each feedback contributes equally to global trust
    const totalLocalTrust = feedbackList.reduce((total, feedback) => {
      const feedbackParams = {
        A: feedback.positiveFeedbackCount,
        Av: feedback.averageRating,
        C: feedback.completedTransactions,
        Cr: feedback.customerRetentionRate,
        R: feedback.reliabilityScore
      };
      return total + calculateLocalTrust(feedbackParams);
    }, 0);
  
    return totalLocalTrust / feedbackList.length; // Average local trust as global trust
  }
  
  // Function to derive reputation from global trust
  function deriveReputationFromGlobalTrust(globalTrust) {
    // Placeholder: Direct mapping for demonstration purposes
    return globalTrust;
  }
  
  // Function to categorize SP based on the reputation score
  function categorizeReputation(reputation) {
    if (reputation >= 0.7) {
      return 'white';
    } else if (reputation < 0.3) {
      return 'black';
    } else {
      return 'grey';
    }
  }



// Serve Dashboard Pages
app.get('/dashboard/provider', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', 'views', 'provider_dashboard.html'));
});

app.get('/dashboard/requester', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', 'views', 'requester_dashboard.html'));
});

// Backend route to handle logout (if using sessions)
app.post('/logout', (req, res) => {
  // Destroy the session
  req.session.destroy(err => {
      if (err) {
          return res.status(500).json({ message: 'Error logging out' });
      }
      res.clearCookie('sessionId'); // Clear session cookie
      res.status(200).json({ message: 'Logged out successfully' });
  });
});

  
// Start the server
const PORT = process.env.PORT || 3002;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
