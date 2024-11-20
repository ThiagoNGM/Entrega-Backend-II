document.getElementById('loginForm')
    .addEventListener('submit', async (e) => {
        e.preventDefault();

        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;

        const response = await fetch('/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email, password })
        });

        if (response.ok) {
            console.log('Login exitoso');
            window.location.href = '/current'; // Redirigir al usuario a su página de inicio
        } else {
            console.error('Error en el login');
        }

    });