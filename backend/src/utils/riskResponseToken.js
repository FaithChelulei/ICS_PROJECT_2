// Short, single-purpose signed tokens for the "This was me" / "This was
// NOT me" links in the risk-alert email. These links are deliberately NOT
// behind the normal session-auth middleware -- the whole point of reaching
// one is that the user's session was just force-revoked, so they have no
// valid bearer token to present. The signed token in the URL is what
// proves intent instead, scoped tightly: bound to one riskScoreId AND one
// specific action (confirm or deny), expiring in 7 days.
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const PURPOSE = 'risk_response';

// Signed with their own key, never the sign-in key, so a sign-in token can
// never pass as an email-link token or the reverse. RISK_TOKEN_SECRET if
// set; otherwise a key derived from JWT_SECRET for this one purpose, so an
// existing install needs no new setting.
function secret() {
  if (process.env.RISK_TOKEN_SECRET) return process.env.RISK_TOKEN_SECRET;
  return crypto.createHmac('sha256', process.env.JWT_SECRET).update('childguard risk-response links').digest('hex');
}

function signRiskResponseToken(riskScoreId, action) {
  return jwt.sign(
    { purpose: PURPOSE, riskScoreId, action },
    secret(),
    { algorithm: 'HS256', expiresIn: '7d' }
  );
}

function verifyRiskResponseToken(token, riskScoreId, action) {
  if (!token) return false;
  let payload;
  try {
    payload = jwt.verify(token, secret(), { algorithms: ['HS256'] });
  } catch (err) {
    return false;
  }
  return (
    payload.purpose === PURPOSE &&
    Number(payload.riskScoreId) === Number(riskScoreId) &&
    payload.action === action
  );
}

module.exports = { signRiskResponseToken, verifyRiskResponseToken };
