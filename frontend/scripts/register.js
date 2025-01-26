document.getElementById('register-form').addEventListener('submit', async function(event){
    event.preventDefault();
    const ownerAddress = document.getElementById('ownerAddress').value;
    const password = document.getElementById('password').value;
    const role = document.querySelector('input[name="role"]:checked').value;

    try {
        const response = await fetch('http://127.0.0.1:3001/users/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                owner_address: ownerAddress,
                password: password,
                role: role
            })
        });

        const data = await response.json();
        console.log('Registration response:', response);
    console.log('Registration data:', data);

        if (!response.ok) {
            throw new Error(data.message || 'An error occurred during registration.');
        }

        alert('Registration successful! You can now log in.');
       // window.location.href = 'http://127.0.0.1:3001/views/login.html'; // Redirect to the login page
       window.location.href = 'http://127.0.0.1:5500/White_Wash_Attack/frontend/views/login.html'; // Redirect to the login page
       //window.location.href = '/views/login.html';


    } catch (error) {
        alert(`Registration failed: ${error.message}`);
    }
});
