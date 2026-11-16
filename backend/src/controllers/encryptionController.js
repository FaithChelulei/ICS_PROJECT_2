// SysAdmin: encryption key status and re-encryption (Admin > Encryption
// Keys). Key MATERIAL never leaves the server -- the API only ever returns
// key ids and short fingerprints. Adding a new key is deliberately not an
// API action: it's done on the server with `npm run key:new`, which writes
// it straight into backend/.env, so keys are never typed into or shown in
// a browser.
const { getStatus, reencryptAll } = require('../services/keyRotation');
const { logAction } = require('../utils/auditLog');
const { scoreAction, logOnlyAction, riskFields } = require('../services/actionScoring');
const { claimApproval, releaseApproval, approvalRequired } = require('../services/approvals');

async function status(req, res) {
  const result = await getStatus();
  await logOnlyAction(req, 'view_encryption_status');
  res.json(result);
}

async function reencrypt(req, res) {
  // Two-person approval (services/approvals.js).
  const approval = await claimApproval(Number(req.body && req.body.approvalId), 'reencrypt_data');
  if (!approval) return approvalRequired(req, res, 'reencrypt_data');
  let result;
  try {
    result = await reencryptAll();
  } catch (err) {
    await releaseApproval(approval.id);
    console.error('[key-rotation] re-encryption failed, rolled back:', err.message);
    return res.status(500).json({ error: `Re-encryption failed and was rolled back: ${err.message}` });
  }

  // Scored first, so the audit entry below is linked to its risk score.
  const risk = await scoreAction(req, 'reencrypt_data');
  await logAction({
    userId: req.user.id,
    action: 'reencrypt_child_data',
    detail: `active_key=${result.activeKeyId}, rows=${result.updatedRows}, values=${result.updatedValues}, approval_id=${approval.id}`,
    accessRequestId: risk.accessRequestId,
  });
  res.json({ ...result, status: await getStatus(), ...riskFields(risk) });
}

module.exports = { status, reencrypt };
