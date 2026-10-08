// Short, single-purpose signed tokens for the "This was me" / "This was
// NOT me" links in the risk-alert email. These links are deliberately NOT
// behind the normal session-auth middleware -- the whole point of reaching
// one is that the user's session was just force-revoked, so they have no
// valid bearer token to present. The signed token in the URL is what
// proves intent instead, scoped tightly: bound to one riskScoreId AND one
// specific action (confirm or deny), expiring in 7 days.
const jwt = require('jsonwebtoken');

const PURPOSE = 'risk_response';

function signRiskResponseToken(riskScoreId, action) {
  return jwt.sign(
    { purpose: PURPOSE, riskScoreId, action },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );
}

function verifyRiskResponseToken(token, riskScoreId, action) {
  if (!token) return false;
  let payload;
  try {
    payload = jwt.verify(token, process.env.JWT_SECRET);
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
