require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');

const app = express();
app.use(bodyParser.json());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB Connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// Define Mongoose Schemas
//Service Requesters
const ServiceRequesterSchema = new mongoose.Schema({
    _id: mongoose.Schema.Types.ObjectId, // Unique identifier for the document
    owner_address: {
      type: String,
      required: true,
      unique: true // Ensures the blockchain owner address is unique
    },
    ip_address: {
      type: String,
      required: true // Assumes that IP address is required
    },
    location: {
      type: String,
      required: false // Location can be optional or determined from the IP address if needed
    },

    banned_status: {
      is_banned: { type: Boolean, default: false },
      is_permanent: { type: Boolean, default: false },
      banned_until: { type: Date },
      reason: { type: String, default: "" }
    },
  });
    
//Service Providers 
const ServiceSchema = new mongoose.Schema({
    service_id: mongoose.Schema.Types.ObjectId,
    name: {
      type: String,
      required: true
    },
    description: String,
    is_active: {
      type: Boolean,
      default: true
    }
  });
  
  const BannedDetailsSchema = new mongoose.Schema({
    is_permanent: {
      type: Boolean,
      default: false
    },
    banned_until: Date,
    reason: String
  });
  
  const TrustReputationSchema = new mongoose.Schema({
    score: {
      type: Number,
      required: true
    },
    category: {
      type: String,
      required: true,
      enum: ['white', 'grey', 'black'] // only valid categories
    }
  });
  
  const ServiceProviderSchema = new mongoose.Schema({
    _id: mongoose.Schema.Types.ObjectId,
    owner_address: {
      type: String,
      required: true,
      unique: true
    },
    services_offered: [ServiceSchema],
    is_banned: {
      type: Boolean,
      default: false
    },
    banned_details: BannedDetailsSchema,
    trust_reputation: TrustReputationSchema
  });

//FeedBack  
const FeedbackSchema = new mongoose.Schema({
    _id: mongoose.Schema.Types.ObjectId,
    service_requester_id: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      ref: 'ServiceRequester' // This assumes you have a ServiceRequester model
    },
    service_provider_id: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      ref: 'ServiceProvider' // This assumes you have a ServiceProvider model
    },
    service_id: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      ref: 'Service' // This assumes you have a Service model
    },
    rating: {
      type: Number,
      required: true,
      min: 1, // a rating scale of 1-100
      max: 100
    },
    comment: {
      type: String,
      required: false
    },
    created_at: {
      type: Date,
      default: Date.now
    }
  });


// Create Mongoose Models
const ServiceRequester = mongoose.model('ServiceRequester', ServiceRequesterSchema);
const ServiceProvider = mongoose.model('ServiceProvider', ServiceProviderSchema);
const Feedback = mongoose.model('Feedback', FeedbackSchema);

            // Defining Service Providers API endpoints
//Register a New SP
app.post('/service_providers', async (req, res) => {
    const { owner_address, services_offered } = req.body;
    try {
      const serviceProvider = new ServiceProvider({
        owner_address,
        services_offered, // Assuming services_offered is an array of service objects
        is_banned: false, // Default value
        banned_details: {}, // Default empty object
        trust_reputation: { score: 0 } // Initially, only the score is set
      });
  
      const savedServiceProvider = await serviceProvider.save();
      res.status(201).json(savedServiceProvider);
    } catch (error) {
      res.status(500).json({ message: 'Error registering service provider', error });
    }
  });
  
//Retrieve SP details
app.get('/service_providers/:id', async (req, res) => {
    try {
      const serviceProvider = await ServiceProvider.findById(req.params.id);
      if (!serviceProvider) {
        return res.status(404).json({ message: 'Service Provider not found' });
      }
      res.status(200).json(serviceProvider);
    } catch (error) {
      res.status(500).json({ message: 'Error retrieving service provider', error });
    }
  });

//Add a New Service to a SP 
app.put('/service_providers/:id/services', async (req, res) => {
    const { service } = req.body; // Assuming service is an object containing name, description, etc.
    try {
      const updatedServiceProvider = await ServiceProvider.findByIdAndUpdate(
        req.params.id,
        { $push: { services_offered: service } },
        { new: true }
      );
      if (!updatedServiceProvider) {
        return res.status(404).json({ message: 'Service Provider not found' });
      }
      res.status(200).json(updatedServiceProvider);
    } catch (error) {
      res.status(500).json({ message: 'Error adding new service', error });
    }
  });

// Remove a service from a service provider 
app.delete('/service_providers/:id/services/:service_id', async (req, res) => {
    try {
      const updatedServiceProvider = await ServiceProvider.findByIdAndUpdate(
        req.params.id,
        { $pull: { services_offered: { _id: req.params.service_id } } },
        { new: true }
      );
      if (!updatedServiceProvider) {
        return res.status(404).json({ message: 'Service Provider not found' });
      }
      res.status(200).json(updatedServiceProvider);
    } catch (error) {
      res.status(500).json({ message: 'Error removing service', error });
    }
  });
  
//Update a SP's Ban status 
app.put('/service_providers/:id/ban', async (req, res) => {
    const { is_banned, is_permanent, banned_until, reason } = req.body;
    try {
      const updatedServiceProvider = await ServiceProvider.findByIdAndUpdate(
        req.params.id,
        { is_banned, banned_details: { is_permanent, banned_until, reason } },
        { new: true }
      );
      if (!updatedServiceProvider) {
        return res.status(404).json({ message: 'Service Provider not found' });
      }
      res.status(200).json(updatedServiceProvider);
    } catch (error) {
      res.status(500).json({ message: 'Error updating banned status', error });
    }
  });
  
//Retrieve the Trust Reputation of a Service Provider
app.get('/service_providers/:id/trust_reputation', async (req, res) => {
    try {
      const serviceProvider = await ServiceProvider.findById(req.params.id);
      if (!serviceProvider) {
        return res.status(404).json({ message: 'Service Provider not found' });
      }
      res.status(200).json({ trust_reputation: serviceProvider.trust_reputation });
    } catch (error) {
      res.status(500).json({ message: 'Error retrieving trust reputation', error });
    }
  });
  
            // Defining Services API endpoints
//List All Active Services (Embedded Service Approach)
app.get('/services', async (req, res) => {
    try {
      const serviceProviders = await ServiceProvider.find({ 'services_offered.is_active': true });
      const activeServices = serviceProviders.reduce((acc, sp) => {
        const activeServicesOfSp = sp.services_offered.filter(service => service.is_active);
        return acc.concat(activeServicesOfSp);
      }, []);
      res.status(200).json(activeServices);
    } catch (error) {
      res.status(500).json({ message: 'Error retrieving active services', error });
    }
  });
  
//Retrieve Details of a Specific Service
//This endpoint retrieves the details of a specific service by its ID. This example assumes you would have to search through each service provider's list of services to find the matching service.
app.get('/services/:id', async (req, res) => {
    try {
      const serviceId = req.params.id;
      const serviceProvider = await ServiceProvider.findOne({ 'services_offered._id': serviceId });
      if (!serviceProvider) {
        return res.status(404).json({ message: 'Service not found' });
      }
      const service = serviceProvider.services_offered.find(service => service._id.toString() === serviceId);
      res.status(200).json(service);
    } catch (error) {
      res.status(500).json({ message: 'Error retrieving service details', error });
    }
  });
  

            // Defining Service Requester API endpoints
// Register a Service Requester
app.post('/register-service-requester', async (req, res) => {
    try {
      const newServiceRequester = new ServiceRequester({
        owner_address: req.body.owner_address,
        ip_address: req.body.ip_address,
        location: req.body.location, // optional
        banned_status: {
          is_banned: false, // default
          is_permanent: false, // default
        }
      });
  
      const savedServiceRequester = await newServiceRequester.save();
      res.status(201).json(savedServiceRequester);
    } catch (error) {
      res.status(500).json({ message: 'Error registering service requester', error });
    }
  });

  // API Endpoint to submit feedback
  app.post('/submit-feedback', async (req, res) => {
    try {
      const newFeedback = new Feedback({
        service_requester_id: req.body.service_requester_id,
        service_provider_id: req.body.service_provider_id,
        service_id: req.body.service_id,
        rating: req.body.rating,
        comment: req.body.comment
      });
  
      const savedFeedback = await newFeedback.save();
      res.status(201).json(savedFeedback);
    } catch (error) {
      res.status(500).json({ message: 'Error submitting feedback', error });
    }
  });
  
  // API Endpoint to check ban status of a Service Requester
  app.get('/check-ban/:requesterId', async (req, res) => {
    try {
      const serviceRequester = await ServiceRequester.findById(req.params.requesterId);
      if (!serviceRequester) {
        return res.status(404).json({ message: 'Service Requester not found' });
      }
  
      res.status(200).json({ banned_status: serviceRequester.banned_status });
    } catch (error) {
      res.status(500).json({ message: 'Error checking ban status', error });
    }
  });
  
  // API Endpoint to update the banned status of a Service Requester
  app.put('/update-ban/:requesterId', async (req, res) => {
    try {
      const { is_banned, is_permanent, banned_until, reason } = req.body;
      const updatedServiceRequester = await ServiceRequester.findByIdAndUpdate(
        req.params.requesterId,
        {
          banned_status: { is_banned, is_permanent, banned_until, reason }
        },
        { new: true }
      );
  
      if (!updatedServiceRequester) {
        return res.status(404).json({ message: 'Service Requester not found' });
      }
  
      res.status(200).json(updatedServiceRequester);
    } catch (error) {
      res.status(500).json({ message: 'Error updating ban status', error });
    }
  });
  
 
            // FeedBack EndPoints
//Retrieve All Feedback for a Specific Service Provider
app.get('/feedback/service_providers/:sp_id', async (req, res) => {
    try {
      const spId = req.params.sp_id;
      const feedback = await Feedback.find({ service_provider_id: spId });
      if (!feedback.length) {
        return res.status(404).json({ message: 'No feedback found for this service provider' });
      }
      res.status(200).json(feedback);
    } catch (error) {
      res.status(500).json({ message: 'Error retrieving feedback for service provider', error });
    }
  });
  
//Retrieve All Feedback for a Specific Service
app.get('/feedback/services/:service_id', async (req, res) => {
    try {
      const serviceId = req.params.service_id;
      const feedback = await Feedback.find({ service_id: serviceId });
      if (!feedback.length) {
        return res.status(404).json({ message: 'No feedback found for this service' });
      }
      res.status(200).json(feedback);
    } catch (error) {
      res.status(500).json({ message: 'Error retrieving feedback for service', error });
    }
  });
  


            // Trust and Reputation Management Endpoints
// Calculate the global trust and reputation for a service provider
app.post('/reputation/calculate/:sp_id', async (req, res) => {
    try {
      const sp_id = req.params.sp_id;
      
      // Fetch all feedback for the specific service provider
      const feedbackList = await Feedback.find({ service_provider_id: sp_id });
  
      // Assuming 'calculateLocalTrust' is a function that calculates local trust for each feedback
      const localTrustValues = feedbackList.map(feedback => calculateLocalTrust(feedback));
  
      // Calculate global trust as the weighted sum of all local trust values
      const globalTrust = calculateGlobalTrust(localTrustValues);
  
      // Derive the reputation from the global trust value
      const reputation = deriveReputationFromGlobalTrust(globalTrust);
  
      // Determine the category based on the reputation score
      const category = categorizeReputation(reputation);
  
      // Update the service provider's trust reputation in the database
      const updatedServiceProvider = await ServiceProvider.findByIdAndUpdate(
        sp_id,
        { 'trust_reputation.score': reputation, 'trust_reputation.category': category },
        { new: true }
      );
  
      if (!updatedServiceProvider) {
        return res.status(404).json({ message: 'Service Provider not found' });
      }
  
      res.status(200).json({ trust_reputation: updatedServiceProvider.trust_reputation });
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

            //Registration Endpoint 
app.post('/register-service-requester', async (req, res) => {
    const { owner_address, ip_address, location } = req.body;

    try {
        // Check if the service requester is on the banned lists
        const isBanned = await ServiceRequester.findOne({
            owner_address,
            $or: [
                { 'banned_status.is_banned': true, 'banned_status.is_permanent': true },
                { 'banned_status.is_banned': true, 'banned_status.banned_until': { $gte: new Date() } }
            ]
        });

        if (isBanned) {
            // If the user is banned (permanently or temporarily with a ban that has not yet expired), deny access
            return res.status(403).json({ message: 'Access denied. Your account is banned.' });
        }

        // If the user is not banned, proceed with registration
        const newServiceRequester = new ServiceRequester({
            _id: new mongoose.Types.ObjectId(),
            owner_address,
            ip_address,
            location,
            banned_status: {
                is_banned: false,
                is_permanent: false
            }
        });

        const savedServiceRequester = await newServiceRequester.save();
        res.status(201).json(savedServiceRequester);
    } catch (error) {
        res.status(500).json({ message: 'Error registering service requester', error });
    }
});
  
// Start the server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});