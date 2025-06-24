document.addEventListener('DOMContentLoaded', async () => {
    const userId = localStorage.getItem('userId');
    const token = localStorage.getItem('userToken');
    const ownerAddress = localStorage.getItem('userAddress');

    if (!userId || !token) {
        window.location.href = 'http://127.0.0.1:5500/White_Wash_Attack/frontend/views/login.html';
        return;
    }

    // Function to refresh availed services
    const refreshAvailedServices = async () => {
        try {
            const response = await fetch(`http://127.0.0.1:3001/users/${userId}`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            
            if (!response.ok) {
                throw new Error('Failed to fetch user data');
            }
            
            const user = await response.json();
            const availedServicesList = document.getElementById('availedServicesList');
            availedServicesList.innerHTML = ''; // Clear previous entries

            if (user.services_availed && user.services_availed.length > 0) {
                user.services_availed.forEach(service => {
                    const li = document.createElement('li');
                    li.innerHTML = `
                        <strong>${service.name || 'Unknown Service'}</strong>: ${service.description || 'No description'}
                        <button onclick="submitFeedback('${service._id || service.service_id}', '${service.provider_id}')" class="btn btn-primary btn-sm">
                            Submit Feedback
                        </button>
                    `;
                    availedServicesList.appendChild(li);
                });
            } else {
                const li = document.createElement('li');
                li.innerText = 'No services availed yet.';
                availedServicesList.appendChild(li);
            }
            
        } catch (error) {
            console.error('Error fetching availed services:', error);
            const availedServicesList = document.getElementById('availedServicesList');
            availedServicesList.innerHTML = '<li>Error loading availed services</li>';
        }
    };

    // Call refreshAvailedServices to load initially
    refreshAvailedServices();

    // Fetch User Data and Populate Dashboard
    try {
        const response = await fetch(`http://127.0.0.1:3001/users/${userId}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!response.ok) {
            throw new Error('Failed to fetch user data');
        }

        const user = await response.json();
        console.log('User data:', user);

        // Safely access trust_reputation with fallback
        const trustScore = user.trust_reputation?.score ?? 0;

        // Populate user information
        document.getElementById('requester-info').innerHTML = `
            <p>Owner Address: ${ownerAddress}</p>
            <p>Trust Score: ${trustScore}</p>
        `;

    } catch (error) {
        console.error('Error fetching user data:', error);
        // Display user-friendly error message
        document.getElementById('requester-info').innerHTML = `
            <p>Owner Address: ${ownerAddress}</p>
            <p>Trust Score: 0 (Error loading user data)</p>
        `;
    }

    // Fetch Available Services
    try {
        const servicesResponse = await fetch('http://127.0.0.1:3001/services', {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!servicesResponse.ok) {
            throw new Error('Failed to fetch services');
        }

        const services = await servicesResponse.json();
        console.log('Available services:', services);

        // Populate available services list
        const servicesList = document.getElementById('availableServicesList');
        servicesList.innerHTML = ''; // Clear previous entries

        // Check if services is an array
        if (Array.isArray(services) && services.length > 0) {
            services.forEach(service => {
                const li = document.createElement('li');
                li.innerHTML = `
                    <strong>${service.name}</strong>: ${service.description}
                    <button onclick="availService('${service._id}')">Avail Service</button>
                `;
                servicesList.appendChild(li);
            });
        } else {
            // Handle case where no services are available
            const li = document.createElement('li');
            li.innerText = 'No services available at the moment.';
            servicesList.appendChild(li);
        }
    } catch (error) {
        console.error('Error fetching services:', error);
        const servicesList = document.getElementById('availableServicesList');
        servicesList.innerHTML = '<li>Error loading services. Please try again later.</li>';
    }

    // Function to Avail a Service
    window.availService = async (serviceId) => {
        try {
            const availResponse = await fetch(`http://127.0.0.1:3001/users/${userId}/avail-service`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ serviceId: serviceId })
            });

            if (availResponse.ok) {
                alert('Service availed successfully');
                // Refresh the availed services list instead of reloading the entire page
                refreshAvailedServices();
            } else {
                const errorText = await availResponse.text();
                console.error('Error availing service:', errorText);
                alert('Error availing service. Please try again.');
            }
        } catch (error) {
            console.error('Error availing service:', error);
            alert('Error availing service. Please check your connection and try again.');
        }
    };

    // Global function to submit feedback (accessible from HTML)
    window.submitFeedback = (serviceId, providerId) => {
        if (!serviceId || !providerId) {
            alert('Missing service or provider information');
            return;
        }
        
        // Navigate to feedback page with parameters
        const feedbackUrl = `feedback.html?serviceId=${encodeURIComponent(serviceId)}&providerId=${encodeURIComponent(providerId)}`;
        window.location.href = feedbackUrl;
    };

    // Attach the logout function to the logout button
    const logoutButton = document.getElementById('logoutButton');
    if (logoutButton) {
        logoutButton.addEventListener('click', logout);
    } else {
        console.warn('Logout button not found');
    }
});

// Logout function to clear session and redirect to login page
const logout = () => {
    localStorage.removeItem('userToken');   // Remove JWT token
    localStorage.removeItem('userId');      // Remove user ID
    localStorage.removeItem('userAddress'); // Remove user address
    window.location.href = 'http://127.0.0.1:5500/White_Wash_Attack/frontend/views/login.html';
};