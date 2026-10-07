// Minimal audit-log writer. Proposal 3.5 requires every access to child
// data to leave an immutable trail — this is the one place that trail is
// written, so every record route calls through here rather than writing
// to audit_log ad hoc. The app's DB role should never get UPDATE/DELETE on
// audit_log (see the note in schema.sql) — INSERT + SELECT only.
const db = require('../config/db');

async function logAction({ userId, action, detail = null, accessRequestId = null }) {
  await db.query(
    `INSERT INTO audit_log (access_request_id, user_id, action, detail)
     VALUES ($1, $2, $3, $4)`,
    [accessRequestId, userId, action, detail]
  );
}

module.exports = { logAction };
