// SysAdmin account-recovery actions. Built specifically to close the loop
// left open by riskResponseController.js's deny() handler: when an owner
// clicks "This was NOT me", the account is locked and told to "contact a
// System Administrator" -- this is the SysAdmin side of that, giving them
// an actual way to act on it instead of a dead end.
const bcrypt = require('bcryptjs');
const db = require('../config/db');
const { logAction } = require('../utils/auditLog');
const { sendAccountUnlockedEmail } = require('../utils/mailer');
const { generateTempPassword } = require('../utils/tempPassword');

// GET /admin/users/locked — SysAdmin only. Lists every currently-locked
// account so the SysAdmin doesn't need direct DB access to find out who
// needs attention, and can see why each one was locked.
async function listLockedUsers(req, res) {
  const { rows } = await db.query(
    `SELECT u.id, u.email, r.name AS role, u.locked_reason, u.created_at
     FROM users u JOIN roles r ON r.id = u.role_id
     WHERE u.is_locked = TRUE
     ORDER BY u.id ASC`
  );
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

  res.json({ message: `Account unlocked. New temporary password emailed to ${user.email}.` });
}

module.exports = { listLockedUsers, unlockAccount };
