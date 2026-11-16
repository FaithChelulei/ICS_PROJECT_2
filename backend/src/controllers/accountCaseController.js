// "Take action" cases (db/013_account_cases.sql), handled on the website:
//   auditor reports (weekly review) -> admin pauses until verified ->
//   the person explains -> an admin decides: verified or access removed.
// Separation of duties: the auditor identifies, the admin acts on the
// account, and nobody can report, pause or decide their own case (also a
// database CHECK). Every step is risk-scored and written to the audit log.
const db = require('../config/db');
const { logAction } = require('../utils/auditLog');
const { scoreAction, logOnlyAction, RISK_NOTICE } = require('../services/actionScoring');

const OPEN = ['reported', 'paused', 'explained'];
const NOTE_MIN = 10;
const text = (v, max = 2000) => (typeof v === 'string' ? v.trim().slice(0, max) : '');

// Called when a week is marked "Take action": opens a case unless the
// person already has an open one. Returns the case id (new or existing).
async function openCaseFromReview({ userId, weeklyReviewId, reportedBy, note }) {
  const { rows: open } = await db.query(
    'SELECT id FROM account_cases WHERE user_id = $1 AND status = ANY($2)', [userId, OPEN]);
  if (open[0]) return open[0].id;
  const { rows } = await db.query(
    `INSERT INTO account_cases (user_id, weekly_review_id, reported_by, report_note)
     VALUES ($1, $2, $3, $4) RETURNING id`, [userId, weeklyReviewId, reportedBy, note]);
  await logAction({ userId: reportedBy, action: 'account_case_reported', detail: `case_id=${rows[0].id}, person=${userId}, weekly_review_id=${weeklyReviewId}` });
  return rows[0].id;
}

// ------------------------------------------------------------- the person

// GET /auth/paused-case -- what a paused person sees (no child data).
async function myCase(req, res) {
  const { rows } = await db.query(
    `SELECT c.id, c.status, c.paused_at, c.explanation, c.explained_at, wr.week_label
     FROM account_cases c LEFT JOIN weekly_reviews wr ON wr.id = c.weekly_review_id
     WHERE c.user_id = $1 AND c.status IN ('paused', 'explained') ORDER BY c.id DESC LIMIT 1`, [req.user.id]);
  await logOnlyAction(req, 'view_paused_case');
  if (!rows[0]) return res.json({ paused: false });
  const c = rows[0];
  res.json({ paused: true, caseId: c.id, status: c.status, week: c.week_label, pausedAt: c.paused_at,
    explanation: c.explanation, explainedAt: c.explained_at });
}

// POST /auth/paused-case/explanation { explanation }
async function explain(req, res) {
  const explanation = text(req.body && req.body.explanation);
  if (explanation.length < NOTE_MIN) {
    return res.status(400).json({ error: `Please explain in at least ${NOTE_MIN} characters.` });
  }
  const { rows } = await db.query(
    `UPDATE account_cases SET status = 'explained', explanation = $2, explained_at = now()
     WHERE user_id = $1 AND status IN ('paused', 'explained') RETURNING id`, [req.user.id, explanation]);
  if (!rows[0]) return res.status(409).json({ error: 'Your access is not paused.', code: 'NOT_PAUSED' });
  await logOnlyAction(req, 'explain_paused_case');
  await logAction({ userId: req.user.id, action: 'account_case_explained', detail: `case_id=${rows[0].id}` });
  res.json({ caseId: rows[0].id, status: 'explained' });
}

// -------------------------------------------------------- the administrator

// GET /admin/cases -- open cases first, then the last 20 closed ones.
async function listCases(req, res) {
  const { rows } = await db.query(
    `SELECT c.*, u.full_name, u.email, r.name AS role, wr.week_label,
            rb.full_name AS reported_by_name, pb.full_name AS paused_by_name, db_.full_name AS decided_by_name
     FROM account_cases c
     JOIN users u ON u.id = c.user_id JOIN roles r ON r.id = u.role_id
     LEFT JOIN weekly_reviews wr ON wr.id = c.weekly_review_id
     JOIN users rb ON rb.id = c.reported_by
     LEFT JOIN users pb ON pb.id = c.paused_by
     LEFT JOIN users db_ ON db_.id = c.decided_by
     WHERE c.status = ANY($1) OR c.id IN (SELECT id FROM account_cases WHERE status <> ALL($1) ORDER BY decided_at DESC NULLS LAST LIMIT 20)
     ORDER BY (c.status = ANY($1)) DESC, c.reported_at DESC`, [OPEN]);
  await logOnlyAction(req, 'view_account_cases');
  res.json({
    cases: rows.map((c) => ({
      id: c.id, status: c.status, person: c.full_name || c.email, email: c.email, role: c.role, week: c.week_label,
      reportedBy: c.reported_by_name, reportNote: c.report_note, reportedAt: c.reported_at,
      pausedBy: c.paused_by_name, pausedAt: c.paused_at, pauseNote: c.pause_note,
      explanation: c.explanation, explainedAt: c.explained_at,
      decidedBy: c.decided_by_name, decidedAt: c.decided_at, decisionNote: c.decision_note,
      own: c.user_id === req.user.id,
    })),
  });
}

async function findCase(req) {
  const id = Number(req.params.caseId);
  if (!Number.isInteger(id) || id < 1 || id > 2147483647) return null;
  const { rows } = await db.query(
    'SELECT c.*, r.name AS role FROM account_cases c JOIN users u ON u.id = c.user_id JOIN roles r ON r.id = u.role_id WHERE c.id = $1', [id]);
  return rows[0] || null;
}

// POST /admin/cases/:caseId/pause { note, password }  (password: step-up)
async function pause(req, res) {
  const note = text(req.body && req.body.note);
  if (note.length < NOTE_MIN) return res.status(400).json({ error: `Give a reason of at least ${NOTE_MIN} characters.` });
  const c = await findCase(req);
  if (!c) return res.status(404).json({ error: 'Case not found' });
  if (c.user_id === req.user.id) return res.status(403).json({ error: 'You cannot act on your own case.', code: 'OWN_CASE' });
  if (c.status !== 'reported') return res.status(409).json({ error: 'This case is already paused or closed.', code: 'CASE_NOT_REPORTED' });
  const risk = await scoreAction(req, 'pause_account');
  if (risk.flagged) return res.status(401).json({ error: RISK_NOTICE, code: 'SESSION_REVOKED_RISK' });
  await db.transaction(async (client) => {
    await client.query(
      `UPDATE account_cases SET status = 'paused', paused_by = $2, paused_at = now(), pause_note = $3 WHERE id = $1 AND status = 'reported'`,
      [c.id, req.user.id, note]);
    // Every open session ends now; the person signs in again to see the pause.
    await client.query(
      "UPDATE sessions SET revoked_at = now(), revoked_reason = 'account_paused' WHERE user_id = $1 AND revoked_at IS NULL", [c.user_id]);
  });
  await logAction({ userId: req.user.id, action: 'account_paused', detail: `case_id=${c.id}, person=${c.user_id}`, accessRequestId: risk.accessRequestId });
  res.json({ id: c.id, status: 'paused' });
}

// POST /admin/cases/:caseId/decision { decision: 'verified' | 'removed', note, password }
async function decide(req, res) {
  const decision = req.body && req.body.decision;
  if (!['verified', 'removed'].includes(decision)) return res.status(400).json({ error: "decision must be 'verified' or 'removed'" });
  const note = text(req.body.note);
  if (note.length < NOTE_MIN) return res.status(400).json({ error: `Say how you verified it (at least ${NOTE_MIN} characters).` });
  const c = await findCase(req);
  if (!c) return res.status(404).json({ error: 'Case not found' });
  if (c.user_id === req.user.id) return res.status(403).json({ error: 'You cannot act on your own case.', code: 'OWN_CASE' });
  if (!OPEN.includes(c.status)) return res.status(409).json({ error: 'This case is already closed.', code: 'CASE_CLOSED' });
  const risk = await scoreAction(req, 'decide_account_case');
  if (risk.flagged) return res.status(401).json({ error: RISK_NOTICE, code: 'SESSION_REVOKED_RISK' });

  let endedGrants = 0;
  await db.transaction(async (client) => {
    await client.query(
      `UPDATE account_cases SET status = $2, decided_by = $3, decided_at = now(), decision_note = $4 WHERE id = $1`,
      [c.id, decision, req.user.id, note]);
    if (decision === 'removed') {
      await client.query(
        "UPDATE users SET is_locked = TRUE, locked_reason = $2 WHERE id = $1",
        [c.user_id, `Access removed after a review (case ${c.id})`]);
      await client.query(
        "UPDATE sessions SET revoked_at = now(), revoked_reason = 'access_removed' WHERE user_id = $1 AND revoked_at IS NULL", [c.user_id]);
      if (c.role === 'Educator') {
        // Every child shared with this educator: access ends now, and each
        // parent sees "Taken back" on Who Can See My Child.
        const { rowCount } = await client.query(
          `UPDATE educator_access SET status = CASE WHEN status = 'granted' THEN 'revoked' ELSE 'refused' END,
                  ended_at = now(), decided_by = $2, decided_at = COALESCE(decided_at, now())
           WHERE educator_id = $1 AND status IN ('pending', 'granted')`, [c.user_id, req.user.id]);
        endedGrants = rowCount;
      }
    }
  });
  await logAction({
    userId: req.user.id,
    action: decision === 'verified' ? 'account_case_verified' : 'account_access_removed',
    detail: `case_id=${c.id}, person=${c.user_id}${decision === 'removed' && c.role === 'Educator' ? `, child_access_ended=${endedGrants}` : ''}`,
    accessRequestId: risk.accessRequestId,
  });
  res.json({ id: c.id, status: decision, endedGrants });
}

module.exports = { openCaseFromReview, myCase, explain, listCases, pause, decide };
