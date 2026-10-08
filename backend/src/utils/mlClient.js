// Thin client for the Flask ML risk-scoring microservice (ml/service/app.py).
// Uses Node's native fetch (available since v18; this project runs v24, so
// no node-fetch/axios dependency is needed).
const ML_SERVICE_URL = process.env.ML_SERVICE_URL || 'http://127.0.0.1:5001';

// Returns null (never throws) if the ML service is unreachable or errors.
// A missing risk score should never block a caregiver from doing their
// job -- but the failure is still worth knowing about, so it's logged.
async function scoreSession(role, features) {
  try {
    const response = await fetch(`${ML_SERVICE_URL}/score`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ role, features }),
      signal: AbortSignal.timeout(5000),
    });

    if (!response.ok) {
      const body = await response.text();
      console.error(`[ml-service] /score returned ${response.status}: ${body}`);
      return null;
    }

    return await response.json();
  } catch (err) {
    console.error('[ml-service] unreachable:', err.message);
    return null;
  }
}

module.exports = { scoreSession };
