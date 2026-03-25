const URL = 'http://localhost:4000/api/v1/auth/login';
const MAX_REQUESTS = 10;

async function runTest() {
    console.log(`🚀 Lancement du test de charge sur ${URL}...`);
    console.log(`Cible : 5 requêtes autorisées, les suivantes doivent être bloquées.\n`);

    for (let i = 1; i <= MAX_REQUESTS; i++) {
        try {
            const start = Date.now();
            const response = await fetch(URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: 'test@example.com', password: 'Password123' })
            });

            const duration = Date.now() - start;
            const data = await response.json();

            if (response.ok) {
                console.log(`✅ Requête #${i} : SUCCESS (${response.status}) - ${duration}ms`);
            } else {
                console.log(`❌ Requête #${i} : FAILED (${response.status}) - ${data.message}`);
            }
        } catch (error) {
            console.log(`❌ Requête #${i} : ERROR - ${error.message}`);
        }
    }
}

runTest();
