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
    '0x7385a6b0E3D84eF19178e348f164D2f3eEBBe4F3'
);

const DeviceContractRegistry = new web3.eth.Contract(
    DeviceContractRegistryArtifact.abi, 
    '0x37Cac226C49Fe6eED156DA8f19eC74fbAD0051bF'
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

app.use(bodyParser.json());


// Enable CORS for all routes
app.use(cors({
  origin: 'http://127.0.0.1:5500', //  frontend's actual origin 
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

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
  rating: Number,
  comment: String,
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
  trust_reputation: {
    type: {
        score: { type: Number, default: 100 },
        category: { type: String, enum: ['white', 'grey', 'black'] }
    },
    required: function () { return this.role === 'provider'; },
    default: undefined
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
  required: function () { return this.role === 'provider'; },
  default: {} // means banned_details is always initialized
},
  // Fields specific to requesters
  services_availed: {
    type: [ServiceAvailedSchema],
    required: function () { return this.role === 'requester'; },
    default: undefined
},
feedback: {
    type: [FeedbackSchema],
    required: function () { return this.role === 'requester'; },
    default: undefined
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
// Register a New User (Service Provider or Requester)
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

  try {
      const existingUser = await User.findOne({ owner_address });
      if (existingUser) {
          return res.status(409).json({ message: "User already exists." });
      }

      // Assign an unassigned device identifier
      const availableDevice = deviceIdentifiers.find(device => device.assigned === false);
      if (!availableDevice) {
          return res.status(500).json({ message: "No available device identifiers." });
      }

      availableDevice.assigned = true; // Mark as assigned
      fs.writeFileSync(path.resolve(__dirname, 'device_identifiers.json'), JSON.stringify(deviceIdentifiers, null, 2)); // Save the changes

      const newUser = new User({
          owner_address,
          password,
          role,
          ip_address: req.ipAddress,
          device_info: availableDevice, // Store the assigned device info
      });

      if (role === 'provider') {
          newUser.services_offered = [];
          newUser.trust_reputation = { score: 100, category: 'white' };
          newUser.banned_details = {
              is_banned: false,
              is_permanent: false,
              banned_until: null,
              reason: ''
          };
      } else if (role === 'requester') {
          newUser.services_availed = [];
          newUser.feedback = [];
      }


      // Save the new user to the database
      const savedUser = await newUser.save();

      try {
          // Register the device on the blockchain
          await addDevice(availableDevice.ipAddress, availableDevice.imei, availableDevice.macAddress);
          res.status(201).json(savedUser);
      } catch (blockchainError) {
          console.error('Error registering device on blockchain:', blockchainError);
          res.status(500).json({ message: 'Error registering device on blockchain.', error: blockchainError });
      }

  } catch (error) {
      console.error(error);
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


// Avail a Service (Requester Only)
app.post('/users/:id/avail-service', async (req, res) => {
  const { serviceId } = req.body;
  const userId = req.params.id;

  try {
      // Find the service in the database
      const serviceProvider = await User.findOne({ 'services_offered._id': serviceId, role: 'provider' });
      if (!serviceProvider) {
          return res.status(404).json({ message: 'Service not found' });
      }

      const availedService = serviceProvider.services_offered.id(serviceId);

      // Update the requester's availed services
      const requester = await User.findByIdAndUpdate(
          userId,
          { $push: { services_availed: availedService } }, // Use $push to append to the array
          { new: true, runValidators: true }
      );

      if (!requester) {
          return res.status(404).json({ message: 'Requester not found' });
      }

      res.status(200).json({ message: 'Service availed successfully', requester });
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

// Submit Feedback (Requester Only)
app.post('/submit-feedback', async (req, res) => {
  const { user_id, service_id, rating, comment } = req.body;

  try {
      // Find the service provider associated with the given service_id
      const serviceProvider = await User.findOne({ 'services_offered._id': service_id, role: 'provider' });
      if (!serviceProvider) {
          return res.status(404).json({ message: 'Service provider not found' });
      }

      // Initialize feedback array if not present
      if (!serviceProvider.feedback) {
          serviceProvider.feedback = [];
      }

      // Create the feedback object
      const feedback = { rating, comment, service_id, user_id };
      serviceProvider.feedback.push(feedback);

      // Update trust score logic based on the feedback rating
      const totalFeedback = serviceProvider.feedback.length;
      const totalRating = serviceProvider.feedback.reduce((acc, feedback) => acc + feedback.rating, 0);
      const newTrustScore = totalRating / totalFeedback;
      serviceProvider.trust_reputation.score = newTrustScore;

      // Categorize provider based on the updated trust score
      if (newTrustScore >= 70) {
          serviceProvider.trust_reputation.category = 'white';
          serviceProvider.banned_details.is_banned = false; // Ensure they're not banned if whitelisted
      } else if (newTrustScore < 30) {
          serviceProvider.trust_reputation.category = 'black';
          serviceProvider.banned_details.is_banned = true; // Blacklist if trust score is too low
      } else {
          serviceProvider.trust_reputation.category = 'grey';
          serviceProvider.banned_details.is_banned = false; // Not banned but not fully trusted either
      }

      // Save the updated provider information
      await serviceProvider.save();

      res.status(200).json({ message: "Feedback submitted and reputation updated." });
  } catch (error) {
      console.error('Error handling feedback:', error);
      res.status(500).json({ message: "Error submitting feedback.", error });
  }
});


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
