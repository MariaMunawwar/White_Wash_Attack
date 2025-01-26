document.getElementById('login-form').addEventListener('submit', async function(event) {
    event.preventDefault();
    const ownerAddress = document.getElementById('ownerAddress').value;
    const password = document.getElementById('password').value;

    try {
        const response = await fetch('http://127.0.0.1:3001/users/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                owner_address: ownerAddress,
                password: password
            })
        });

        const data = await response.json();

        // Log the full data object
        console.log('Full response data:', data);

        if (!response.ok) {
            throw new Error(data.message || 'An error occurred during login.');
        }

        // Check for the role in data
        console.log('User role:', data.role);

        // Store token and other data
        localStorage.setItem('userToken', data.token);
        localStorage.setItem('userId', data.id);
        localStorage.setItem('userRole', data.role);
        localStorage.setItem('userAddress', ownerAddress);

         // Log the stored userId to verify it
         console.log("Stored userId:", localStorage.getItem('userId'));
         console.log("Stored userToken:", localStorage.getItem('userToken'));
         console.log("Stored userRole:", localStorage.getItem('userRole'));
         console.log("Stored userAddress", localStorage.getItem('userAddress'));

        // Redirect based on role
        if (data.role === 'provider') {
            window.location.href = 'http://127.0.0.1:3001/dashboard/provider';
        } else if (data.role === 'requester') {
            window.location.href = 'http://127.0.0.1:3001/dashboard/requester';
        }        
    } catch (error) {
        alert(`Login failed: ${error.message}`);
    }
});
