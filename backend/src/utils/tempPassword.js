// Shared by registrationController.js (new-account approval) and
// userManagementController.js (account-unlock password reset) -- both
// moments where a SysAdmin action needs to hand a user a fresh one-time
// password by email.
const crypto = require('crypto');

function generateTempPassword() {
  // 16 random bytes, base64url-encoded -- short enough to type from an
  // email, long enough to not be guessable before the forced change.
  return crypto.randomBytes(16).toString('base64url');
}

module.exports = { generateTempPassword };
