// Thin client for the Flask ML risk-scoring microservice (ml/service/app.py).
// Uses Node's native fetch (available since v18; this project runs v24, so
// no node-fetch/axios dependency is needed).
const ML_SERVICE_URL = process.env.ML_SERVICE_URL || 'http://127.0.0.1:5001';
// When hosted, the scoring service only answers requests that carry this
// shared key (ML_SHARED_KEY, the same value on both services); on a laptop
// it is not set and nothing changes.
const mlHeaders = () => ({ 'Content-Type': 'application/json', ...(process.env.ML_SHARED_KEY ? { 'X-ML-Key': process.env.ML_SHARED_KEY } : {}) });
// Lazy: scoringHealth -> auditLog -> db would otherwise load at require time.
const health = () => require('../services/scoringHealth');

// Returns null (never throws) if the ML service is unreachable or errors.
// A missing risk score should never block a caregiver from doing their
// job -- but the failure is still worth knowing about, so it's logged.
async function scoreSession(role, features) {
  try {
    const response = await fetch(`${ML_SERVICE_URL}/score`, {
      method: 'POST',
      headers: mlHeaders(),
      body: JSON.stringify({ role, features }),
      signal: AbortSignal.timeout(5000),
    });

    if (!response.ok) {
      const body = await response.text();
      console.error(`[ml-service] /score returned ${response.status}: ${body}`);
      if (response.status >= 500) health().markDown(`score ${response.status}`);
      return null;
    }

    const result = await response.json();
    health().markUp();
    return result;
  } catch (err) {
    console.error('[ml-service] unreachable:', err.message);
    health().markDown(err.message);
    return null;
  }
}

// Layer 2 (weekly review). Same rule: null instead of throwing. A whole
// week of sessions takes longer than one action, so the time limit is
// longer; it runs in the background, never inside a user's request.
async function scoreWeek(date, sessions, localLines = null) {
  try {
    const response = await fetch(`${ML_SERVICE_URL}/score_week`, {
      method: 'POST',
      headers: mlHeaders(),
      body: JSON.stringify(localLines ? { date, sessions, local_lines: localLines } : { date, sessions }),
      signal: AbortSignal.timeout(60000),
    });
    if (!response.ok) {
      console.error(`[ml-service] /score_week returned ${response.status}: ${await response.text()}`);
      return null;
    }
    return await response.json();
  } catch (err) {
    console.error('[ml-service] /score_week unreachable:', err.message);
    return null;
  }
}

module.exports = { scoreSession, scoreWeek };
