// SysAdmin account-recovery actions. Built specifically to close the loop
// left open by riskResponseController.js's deny() handler: when an owner
// clicks "This was NOT me", the account is locked and told to "contact a
// System Administrator" -- this is the SysAdmin side of that, giving them
// an actual way to act on it instead of a dead end.
const bcrypt = require('bcryptjs');
const db = require('../config/db');
const { logAction } = require('../utils/auditLog');
const { sendAccountUnlockedEmail, sendRoleChangedEmail } = require('../utils/mailer');
const { generateTempPassword } = require('../utils/tempPassword');
const { scoreAction, logOnlyAction, riskFields } = require('../services/actionScoring');
const { cleanReason } = require('../utils/changeReason');

// The automated test suites lock their own accounts between runs. Those
// need nobody's attention, so they stay out of the admin's locked list and
// counts.
const TEST_ACCOUNT_LOCK_REASON = 'automated test account';

// GET /admin/users — SysAdmin only. Everyone who can sign in, with the number
// of children linked to them. Row-level security hides child data from a
// SysAdmin, so the count runs as System and returns numbers only, no names.
async function listUsers(req, res) {
  const { rows } = await db.query(
    `SELECT u.id, u.email, u.full_name, r.name AS role, u.is_locked
     FROM users u JOIN roles r ON r.id = u.role_id
     WHERE COALESCE(u.locked_reason, '') NOT LIKE $1
     ORDER BY r.name, u.full_name`,
    [`${TEST_ACCOUNT_LOCK_REASON}%`]
  );
  const { rows: counts } = await db.runAsSystem(() => db.query(
    'SELECT caregiver_id, COUNT(*)::int AS children FROM child_profiles GROUP BY caregiver_id'
  ));
  const children = new Map(counts.map((c) => [c.caregiver_id, c.children]));
  await logOnlyAction(req, 'view_user_list');
  res.json({ users: rows.map((u) => ({ ...u, children: children.get(u.id) || 0 })) });
}

// GET /admin/users/locked — SysAdmin only. Lists every currently-locked
// account so the SysAdmin doesn't need direct DB access to find out who
// needs attention, and can see why each one was locked.
async function listLockedUsers(req, res) {
  const { rows } = await db.query(
    `SELECT u.id, u.email, r.name AS role, u.locked_reason, u.created_at
     FROM users u JOIN roles r ON r.id = u.role_id
     WHERE u.is_locked = TRUE AND COALESCE(u.locked_reason, '') NOT LIKE $1
     ORDER BY u.id ASC`,
    [`${TEST_ACCOUNT_LOCK_REASON}%`]
  );
  await logOnlyAction(req, 'view_locked_accounts');
  res.json({ lockedUsers: rows });
}

// POST /admin/users/:id/unlock — SysAdmin only. Resets the password to a
// fresh one-time temp password (same pattern as a new-account approval),
// clears the lock, and -- because the account was locked over suspected
// unauthorized access -- revokes any sessions still open for that user so
// whoever had access before this moment loses it the instant the password
// changes, not just whenever their JWT happens to expire.
async function unlockAccount(req, res) {
  const userId = Number(req.params.id);

  const { rows } = await db.query(
    'SELECT id, email, is_locked FROM users WHERE id = $1',
    [userId]
  );
  const user = rows[0];
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (!user.is_locked) {
    return res.status(409).json({ error: 'Account is not locked' });
  }

  const tempPassword = generateTempPassword();
  const passwordHash = await bcrypt.hash(tempPassword, 10);

  const client = await db.pool.connect();
  try {
    await client.query('BEGIN');

    await client.query(
      `UPDATE users
       SET password_hash = $1, is_locked = FALSE, locked_reason = NULL, must_change_password = TRUE
       WHERE id = $2`,
      [passwordHash, userId]
    );

    await client.query(
      "UPDATE sessions SET revoked_at = now(), revoked_reason = 'account_unlocked_password_reset' WHERE user_id = $1 AND revoked_at IS NULL",
      [userId]
    );

    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    return res.status(500).json({ error: 'Failed to unlock account' });
  } finally {
    client.release();
  }

  await sendAccountUnlockedEmail(user.email, { tempPassword });

  await logAction({
    userId: req.user.id,
    action: 'admin_unlocked_account',
    detail: `unlocked user_id=${userId}, email=${user.email}`,
  });

  // Privileged action on someone else's account -- scored.
  const risk = await scoreAction(req, 'unlock_account');
  res.json({
    message: `Account unlocked. New temporary password emailed to ${user.email}.`,
    ...riskFields(risk),
  });
}

// POST /admin/users/:id/role — SysAdmin only, password required again
// (FR-25). Open sessions end at once because each one carries the old role.
// Nobody can change their own role, which also means the system always keeps
// the admin who made the change. A caregiver with linked children is refused:
// those children would be left with nobody able to see or manage them.
async function changeRole(req, res) {
  const userId = Number(req.params.id);
  const { role } = req.body || {};
  const reason = cleanReason(req.body && req.body.reason);

  if (typeof role !== 'string') return res.status(400).json({ error: 'Choose a role.' });
  if (!reason) return res.status(400).json({ error: 'Give a reason of 10 to 500 characters.' });
  if (userId === req.user.id) {
    return res.status(403).json({ error: 'You cannot change your own role. Ask another System Administrator.', code: 'OWN_ROLE_CHANGE' });
  }

  const { rows: roleRows } = await db.query('SELECT id FROM roles WHERE name = $1', [role]);
  if (!roleRows[0]) return res.status(400).json({ error: 'Unknown role.' });

  const { rows } = await db.query(
    'SELECT u.id, u.email, r.name AS role FROM users u JOIN roles r ON r.id = u.role_id WHERE u.id = $1',
    [userId]
  );
  const user = rows[0];
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.role === role) return res.status(409).json({ error: `This user is already a ${role}.` });

  const { rows: linked } = await db.runAsSystem(() => db.query(
    'SELECT COUNT(*)::int AS n FROM child_profiles WHERE caregiver_id = $1', [userId]
  ));
  if (linked[0].n > 0) {
    return res.status(409).json({
      error: `This caregiver has ${linked[0].n} child profile(s) linked, so their role cannot be changed.`,
      code: 'CAREGIVER_HAS_CHILDREN',
    });
  }

  await db.transaction(async (client) => {
    await client.query('UPDATE users SET role_id = $1 WHERE id = $2', [roleRows[0].id, userId]);
    await client.query(
      "UPDATE sessions SET revoked_at = now(), revoked_reason = 'role_changed' WHERE user_id = $1 AND revoked_at IS NULL",
      [userId]
    );
  });

  await logAction({
    userId: req.user.id,
    action: 'user_role_changed',
    detail: `user_id=${userId}, email=${user.email}, from=${user.role}, to=${role}, reason=${reason}`,
  });
  try {
    await sendRoleChangedEmail(user.email, { role });
  } catch (err) {
    console.error(`[user-management] role change email to user ${userId} failed:`, err.message);
  }

  const risk = await scoreAction(req, 'change_user_role');
  res.json({ message: `${user.email} is now a ${role} and has been signed out.`, ...riskFields(risk) });
}

module.exports = { listUsers, listLockedUsers, unlockAccount, changeRole, TEST_ACCOUNT_LOCK_REASON };
