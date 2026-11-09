// The refusal when a caregiver asks for a child profile that isn't theirs.
// The attempt is written to the audit log before the refusal is sent: a
// caregiver trying other families' profile numbers is exactly the insider
// behaviour a Security Auditor needs to see.
//
// The answer is the same whether the profile belongs to another family or
// doesn't exist, so the refusal never reveals which profile numbers exist.
// The audit entry keeps the number that was tried, which only the auditor
// sees.
const { logAction } = require('../utils/auditLog');

async function refuseNotOwner(req, res, childProfileId, attemptedAction) {
  await logAction({
    userId: req.user.id,
    action: 'access_denied_not_owner',
    detail: `child_profile_id=${childProfileId}, attempted=${attemptedAction}`,
  });
  return res.status(403).json({ error: 'Not authorized for this child profile', code: 'NOT_YOUR_CHILD' });
}

module.exports = { refuseNotOwner };
