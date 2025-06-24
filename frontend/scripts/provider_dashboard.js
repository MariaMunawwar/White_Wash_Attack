document.addEventListener('DOMContentLoaded', async () => {
    const userId = localStorage.getItem('userId');
    const token = localStorage.getItem('userToken');
    const ownerAddress = localStorage.getItem('userAddress'); 

    if (!userId || !token) {
        window.location.href = 'http://127.0.0.1:5500/White_Wash_Attack/frontend/views/login.html';
        return;
    }

    try {
        const response = await fetch(`http://127.0.0.1:3001/users/${userId}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
    
        if (!response.ok) {
            throw new Error('Failed to fetch user data');
        }
    
        const user = await response.json();
        console.log('User data:', user);

        const score = user.trust_reputation ? user.trust_reputation.score : 'N/A';

        // Display Provider Info and Services
        document.getElementById('provider-info').innerHTML = `
            <p>Owner Address: ${ownerAddress}</p>
            <p>Trust Score: ${user.trust_reputation.score}</p>
        `;

        const servicesList = document.getElementById('servicesList');
        if (user.services_offered && user.services_offered.length > 0) {
            user.services_offered.forEach(service => {
                const li = document.createElement('li');
                li.innerHTML = `<strong>${service.name}</strong>: ${service.description}`;
                const deleteButton = document.createElement('button');
                deleteButton.textContent = 'Delete';
                deleteButton.addEventListener('click', () => {
                    deleteService(service._id);
                });
                li.style.display = 'flex';
                li.style.justifyContent = 'space-between'; 
                li.appendChild(deleteButton);
                servicesList.appendChild(li);
            });
        } else {
            servicesList.innerHTML = `<p>No services offered yet.</p>`;
        }

        // Display Feedback and Ban Status
        const feedbackList = document.getElementById('feedbackList');
        if (user.feedback && user.feedback.length > 0) {
            user.feedback.forEach(feedback => {
                const li = document.createElement('li');
                li.innerText = `Rating: ${feedback.rating}/100 - ${feedback.comment}`;
                feedbackList.appendChild(li);
            });
        } else {
            feedbackList.innerHTML = `<p>No feedback available yet.</p>`;
        }

        const banStatus = user.banned_details.is_banned
            ? `Banned: ${user.banned_details.reason}`
            : "Not Banned";
        document.getElementById('banStatus').innerText = banStatus;

        // Display Whitelist/Greylist/Blacklist Status
        const reputationScore = user.trust_reputation.score;
        let statusText = '';

        if (reputationScore >= 70) {
            statusText = 'Whitelisted';
        } else if (reputationScore < 30) {
            statusText = 'Blacklisted';
        } else {
            statusText = 'Greylisted';
        }

        document.getElementById('status').innerText = `Status: ${statusText}`;
    } catch (error) {
        console.error('Error fetching user data:', error);
    }

    // Handle Add/Update Service
    document.getElementById('addServiceForm').addEventListener('submit', async (event) => {
        event.preventDefault();
        const newService = {
            name: document.getElementById('serviceName').value.trim(),
            description: document.getElementById('serviceDescription').value.trim(),
        };

        try {
            const response = await fetch(`http://127.0.0.1:3001/users/${userId}/services`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ service: newService })
            });

            if (response.ok) {
                location.reload();
            } else {
                console.error('Error adding service:', await response.text());
            }
        } catch (error) {
            console.error('Error adding service:', error);
        }
    });
});

async function deleteService(serviceId) {
    const userId = localStorage.getItem('userId');
    const token = localStorage.getItem('userToken');

    try {
        const response = await fetch(`http://127.0.0.1:3001/users/${userId}/services/${serviceId}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (response.ok) {
            location.reload();
        } else {
            console.error('Error deleting service:', await response.text());
        }
    } catch (error) {
        console.error('Error deleting service:', error);
    }
}

// Logout function to clear session and redirect to login page
const logout = () => {
    localStorage.removeItem('userToken');   // Remove JWT token
    localStorage.removeItem('userId');      // Remove user ID
    localStorage.removeItem('userAddress'); // Remove user address
   // window.location.href = '/views/login.html';// Redirect to the login page
  // window.location.href = 'http://127.0.0.1:3001/login.html'; 
  window.location.href = 'http://127.0.0.1:5500/White_Wash_Attack/frontend/views/login.html';
};

// Attach the logout function to the logout button
document.getElementById('logoutButton').addEventListener('click', logout);

