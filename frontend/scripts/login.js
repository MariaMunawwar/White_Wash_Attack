// Use consistent base URL throughout your frontend
const API_BASE_URL = 'http://127.0.0.1:3001';
const FRONTEND_BASE_URL = 'http://127.0.0.1:5500/White_Wash_Attack/frontend/views';

// Add event listener for login form only if it exists
const loginForm = document.getElementById('login-form');
if (loginForm) {
    loginForm.addEventListener('submit', async function(event) {
        event.preventDefault();
        const ownerAddress = document.getElementById('ownerAddress').value;
        const password = document.getElementById('password').value;

        try {
            console.log('Attempting login with:', { ownerAddress, password });
            
            const response = await fetch(`${API_BASE_URL}/users/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({
                    owner_address: ownerAddress,
                    password: password
                })
            });

            console.log('Response status:', response.status);
            console.log('Response headers:', response.headers);

            if (!response.ok) {
                const errorText = await response.text();
                console.error('Error response:', errorText);
                throw new Error(`HTTP ${response.status}: ${errorText}`);
            }

            const data = await response.json();
            console.log('Full response data:', data);

            // Store token and other data
            localStorage.setItem('userToken', data.token);
            localStorage.setItem('userId', data.id);
            localStorage.setItem('userRole', data.role);
            localStorage.setItem('userAddress', ownerAddress);

            console.log("Stored data:", {
                userId: localStorage.getItem('userId'),
                userToken: localStorage.getItem('userToken'),
                userRole: localStorage.getItem('userRole'),
                userAddress: localStorage.getItem('userAddress')
            });

            // Redirect based on role
            if (data.role === 'provider') {
                window.location.href = `${FRONTEND_BASE_URL}/provider_dashboard.html`;
            } else if (data.role === 'requester') {
                window.location.href = `${FRONTEND_BASE_URL}/requester_dashboard.html`;
            }
        } catch (error) {
            console.error('Login error:', error);
            alert(`Login failed: ${error.message}`);
        }
    });
}

// Add event listener for register form only if it exists
const registerForm = document.getElementById('register-form');
if (registerForm) {
    registerForm.addEventListener('submit', async function(event){
        event.preventDefault();
        const ownerAddress = document.getElementById('ownerAddress').value;
        const password = document.getElementById('password').value;
        const roleElement = document.querySelector('input[name="role"]:checked');
        
        if (!roleElement) {
            alert('Please select a role');
            return;
        }
        
        const role = roleElement.value;

        try {
            console.log('Attempting registration with:', { ownerAddress, password, role });
            
            const response = await fetch(`${API_BASE_URL}/users/register`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({
                    owner_address: ownerAddress,
                    password: password,
                    role: role
                })
            });

            console.log('Registration response status:', response.status);
            console.log('Registration response headers:', response.headers);

            if (!response.ok) {
                const errorText = await response.text();
                console.error('Registration error response:', errorText);
                throw new Error(`HTTP ${response.status}: ${errorText}`);
            }

            const data = await response.json();
            console.log('Registration data:', data);

            alert('Registration successful! You can now log in.');
            window.location.href = `${FRONTEND_BASE_URL}/login.html`;
        } catch (error) {
            console.error('Registration error:', error);
            alert(`Registration failed: ${error.message}`);
        }
    });
}