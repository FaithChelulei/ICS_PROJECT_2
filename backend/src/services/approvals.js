// Two-person approval for the two most powerful actions (DPIA gap G3):
//   reencrypt_data   re-encrypts every stored child value under the newest key
//   apply_retention  permanently anonymises archived profiles
// One System Administrator requests, a DIFFERENT one approves (also a
// database CHECK), and an approval runs the action once, within 24 hours.
// A model cannot protect a handful of powerful people well -- there is too
// little data about them -- so for them a control is used instead.
const db = require('../config/db');

const ACTIONS = {
  reencrypt_data: 're-encrypt all child data under the newest key',
  apply_retention: 'anonymise archived child profiles past the retention period',
};
const VALID_HOURS = 24;

// Claims an approved request for `action` (marks it used). Returns the row,
// or null when there is no usable approval. Atomic: two requests cannot
// use the same approval.
async function claimApproval(approvalId, action) {
  if (!Number.isInteger(approvalId) || approvalId < 1) return null;
  const { rows } = await db.query(
    `UPDATE pending_approvals SET status = 'used', used_at = now()
     WHERE id = $1 AND action = $2 AND status = 'approved'
       AND decided_at > now() - make_interval(hours => $3)
     RETURNING *`,
    [approvalId, action, VALID_HOURS]
  );
  return rows[0] || null;
}

// If the action then fails (and is rolled back), the approval can be used again.
async function releaseApproval(approvalId) {
  await db.query("UPDATE pending_approvals SET status = 'approved', used_at = NULL WHERE id = $1 AND status = 'used'", [approvalId]);
}

// An attempt without a usable approval is still a privileged action: it is
// logged and scored like the action itself (a burst of such attempts is
// exactly what the System Administrator model should see), then refused.
async function approvalRequired(req, res, action) {
  const { scoreAction, riskFields } = require('./actionScoring');
  const { logAction } = require('../utils/auditLog');
  const risk = await scoreAction(req, action);
  await logAction({
    userId: req.user.id,
    action: 'powerful_action_refused_no_approval',
    detail: `action=${action}`,
    accessRequestId: risk.accessRequestId,
  });
  return res.status(409).json({
    error: `To ${ACTIONS[action]}, a second System Administrator must approve it first. Open Approvals to request it.`,
    code: 'APPROVAL_REQUIRED',
    ...riskFields(risk),
  });
}

module.exports = { ACTIONS, VALID_HOURS, claimApproval, releaseApproval, approvalRequired };
