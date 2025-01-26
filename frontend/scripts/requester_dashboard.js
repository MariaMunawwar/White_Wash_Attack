document.addEventListener('DOMContentLoaded', async () => {
    const userId = localStorage.getItem('userId');
    const token = localStorage.getItem('userToken');
    const ownerAddress = localStorage.getItem('userAddress');

    if (!userId || !token) {
        window.location.href = '/login.html';
        return;
    }

    // Function to refresh availed services
    const refreshAvailedServices = async () => {
        try {
            const response = await fetch(`http://127.0.0.1:3001/users/${userId}`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const user = await response.json();
            const availedServicesList = document.getElementById('availedServicesList');
            availedServicesList.innerHTML = ''; // Clear previous entries

            if (user.services_availed) {
                user.services_availed.forEach(service => {
                    const li = document.createElement('li');
                    li.innerText = `${service.name}: ${service.description}`;
                    availedServicesList.appendChild(li);
                });
            }
        } catch (error) {
            console.error('Error fetching availed services:', error);
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

        // Populate user information
        document.getElementById('requester-info').innerHTML = `
            <p>Owner Address: ${ownerAddress}</p>
            <p>Trust Score: ${user.trust_reputation.score}</p>
        `;

        // Populate previously availed services (formerly requested services)
        const availedServicesList = document.getElementById('availedServicesList');
        if (user.services_requested) {
            user.services_requested.forEach(service => {
                const li = document.createElement('li');
                li.innerText = `${service.name}: ${service.description}`;
                availedServicesList.appendChild(li);
            });
        }
    } catch (error) {
        console.error('Error fetching user data:', error);
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
        console.log('Services Response:', servicesResponse); // Check response object
        console.log('Available services:', services);

        // Populate available services list
        const servicesList = document.getElementById('availableServicesList');

        services.forEach(service => {
            const li = document.createElement('li');
            li.innerHTML = `
                <strong>${service.name}</strong>: ${service.description}
                <button onclick="availService('${service._id}')">Avail Service</button>
            `;
            servicesList.appendChild(li);
        });
    } catch (error) {
        console.error('Error fetching services:', error);
        alert('Error fetching available services. Please try again later.'); // Inform the user

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
                location.reload();  // Refresh the page to reflect the newly availed service
            } else {
                console.error('Error availing service:', await availResponse.text());
            }
        } catch (error) {
            console.error('Error availing service:', error);
        }
    };

    // Handle Feedback Submission
    document.getElementById('feedbackForm').addEventListener('submit', async (event) => {
        event.preventDefault();
         // Collect input values
         const serviceId = document.getElementById('serviceId').value;
         const rating = document.getElementById('rating').value;
         const comment = document.getElementById('comment').value;
         const userId = localStorage.getItem('userId');
         const token = localStorage.getItem('userToken');

        try {
            const feedbackResponse = await fetch('http://127.0.0.1:3001/submit-feedback', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({
                    user_id: userId,
                    service_id: serviceId,
                    rating: parseInt(rating), // Convert rating to integer
                    comment: comment
                })
            });

            if (feedbackResponse.ok) {
                alert('Feedback submitted successfully');
                location.reload(); // Reload to update the UI with new trust score
            } else {
                console.error('Error submitting feedback:', await feedbackResponse.text());
            }
        } catch (error) {
            console.error('Error submitting feedback:', error);
        }
    });

});

    // Logout function to clear session and redirect to login page
    const logout = () => {
        localStorage.removeItem('userToken');   // Remove JWT token
        localStorage.removeItem('userId');      // Remove user ID
        localStorage.removeItem('userAddress'); // Remove user address
       // window.location.href = '/views/login.html';  // Redirect to the login page
       window.location.href = 'http://127.0.0.1:3001/login.html'; 
    };
    
    // Attach the logout function to the logout button
    document.getElementById('logoutButton').addEventListener('click', logout);
    