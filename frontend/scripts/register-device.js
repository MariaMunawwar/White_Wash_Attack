document.getElementById('register-device-form').addEventListener('submit', async function(event) {
    event.preventDefault();
    const ownerAddress = document.getElementById('ownerAddress').value;
    const ipHash = document.getElementById('ipHash').value;
    const imeiHash = document.getElementById('imeiHash').value;
    const macHash = document.getElementById('macHash').value;

    try {
        const response = await fetch('/register-device', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                ownerAddress,
                ipHash,
                imeiHash,
                macHash
            })
        });

        if (!response.ok) {
            throw new Error('Error registering device');
        }

        alert('Device registered successfully');
    } catch (error) {
        alert(`Registration failed: ${error.message}`);
    }
});
