// Caregiver-approved access for an Educator (SOFIA Technical SRS 3.1: an
// optional, read-only role with no authority without caregiver approval).
//
// How access starts (db/012): the EDUCATOR asks, by the child's full name
// and a reason. ChildGuard finds active children with that name who are of
// ECD age (3 to 6) and puts the request on each one's PARENT's page; the
// parent grants it for a fixed period (never past the 7th birthday) or
// refuses. The educator's account was verified with the ECD centre by a
// System Administrator before it existed (registrationController).
//
// The request pipeline for an educator reading a child's records is the
// same as for the caregiver, with one more gate:
//   authentication -> role -> the caregiver's GRANT for this child ->
//   records consent -> risk scoring -> response.
// The grant is checked on every request (and again by row-level security,
// db/010_educator_access.sql), so a revocation takes effect at once.
//
// What an educator is given is the minimum for the purpose: the child's
// name, age in years and months, and the developmental records. Never the
// exact date of birth, the family background or the caregiver's details.
const db = require('../config/db');
const { decryptField } = require('../utils/encryption');
const { logAction } = require('../utils/auditLog');
const { hasConsent } = require('../services/consent');
const { scoreAction, scoreIfNewDevice, RISK_NOTICE } = require('../services/actionScoring');
const { lookupPairs, normaliseName } = require('../services/nameIndex');

// From one week up to one school term (about three months); the parent
// grants again next term if they wish.
const GRANT_DAYS = [7, 14, 21, 30, 60, 90];
const DEFAULT_GRANT_DAYS = 30;
// ECD age: from the 3rd birthday until the day before the 7th.
const ECD_MIN_YEARS = 3;
const ECD_END_YEARS = 7;

// "3 years 2 months" -- enough for an educator, without the birth date itself.
function ageText(dateOfBirth, now = new Date()) {
  const dob = new Date(dateOfBirth);
  if (Number.isNaN(dob.getTime())) return null;
  let months = (now.getFullYear() - dob.getFullYear()) * 12 + (now.getMonth() - dob.getMonth());
  if (now.getDate() < dob.getDate()) months -= 1;
  if (months < 0) return null;
  const y = Math.floor(months / 12);
  const m = months % 12;
  const parts = [];
  if (y) parts.push(`${y} year${y === 1 ? '' : 's'}`);
  if (m || !y) parts.push(`${m} month${m === 1 ? '' : 's'}`);
  return parts.join(' ');
}

function birthday(dateOfBirth, years) {
  const dob = new Date(dateOfBirth);
  if (Number.isNaN(dob.getTime())) return null;
  return new Date(Date.UTC(dob.getUTCFullYear() + years, dob.getUTCMonth(), dob.getUTCDate()));
}

// True from the 3rd birthday until the day before the 7th.
function isEcdAge(dateOfBirth, now = new Date()) {
  const from = birthday(dateOfBirth, ECD_MIN_YEARS);
  const until = birthday(dateOfBirth, ECD_END_YEARS);
  return Boolean(from && until) && now >= from && now < until;
}

const publicStatus = (row) => (row.status === 'granted' && new Date(row.expires_at) <= new Date() ? 'expired' : row.status);

const SAME_REPLY = 'Request sent. If this child is on ChildGuard, their parent has been asked. The child appears on this page if the parent agrees.';

// ----------------------------------------------------------- the educator

// POST /educator/access-requests { childName, reason }
//
// The reply is the same whether no child, one child or several children
// matched, so the form cannot be used to find out who is registered. Each
// matching child's parent gets their own request; a parent whose child is
// not the one meant simply refuses it.
async function requestAccess(req, res) {
  const childName = typeof req.body.childName === 'string' ? req.body.childName.trim().replace(/\s+/g, ' ') : '';
  const reason = typeof req.body.reason === 'string' ? req.body.reason.trim() : '';
  if (childName.length > 200 || normaliseName(childName).split(' ').filter(Boolean).length < 2) {
    return res.status(400).json({ error: 'Enter the child’s full name: at least a first name and a family name.' });
  }
  if (reason.length < 10 || reason.length > 500) {
    return res.status(400).json({ error: 'Say why you need access (10 to 500 characters). The parent will read this.' });
  }

  const risk = await scoreIfNewDevice(req, 'request_child_access');
  if (risk.flagged) return res.status(401).json({ error: RISK_NOTICE, code: 'SESSION_REVOKED_RISK' });
  const { rows: ask } = await db.query(
    'INSERT INTO educator_asks (educator_id, child_name, reason) VALUES ($1, $2, $3) RETURNING id, asked_at',
    [req.user.id, childName, reason]);

  // The one lookup outside the educator's own view: blind-index match on the
  // name (nothing is decrypted to search), then the birth date of each match
  // only, to keep ECD-age children. None of it is returned to the educator.
  const pairs = lookupPairs(childName);
  const matched = await db.runAsSystem(async () => {
    const { rows } = await db.query(
      `SELECT cp.id, cp.caregiver_id, ci.date_of_birth_enc
       FROM child_identifiers ci JOIN child_profiles cp ON cp.id = ci.child_profile_id
       JOIN users u ON u.id = cp.caregiver_id
       WHERE cp.archived_at IS NULL AND cp.identity_anonymised_at IS NULL AND NOT u.is_locked
         AND (ci.name_index_key_id, ci.name_index) IN (SELECT * FROM unnest($1::smallint[], $2::char(64)[]))`,
      [pairs.map((p) => p.keyId), pairs.map((p) => p.nameIndex)]);
    const kids = rows.filter((r) => isEcdAge(decryptField(r.date_of_birth_enc)));
    const created = [];
    for (const kid of kids) {
      // Already asked, or already granted and still running: nothing new.
      const { rows: open } = await db.query(
        "SELECT id, status, expires_at FROM educator_access WHERE child_profile_id = $1 AND educator_id = $2 AND status IN ('pending', 'granted')",
        [kid.id, req.user.id]);
      if (open[0] && publicStatus(open[0]) !== 'expired') continue;
      if (open[0]) await db.query("UPDATE educator_access SET status = 'revoked', ended_at = now() WHERE id = $1", [open[0].id]);
      const { rows: made } = await db.query(
        `INSERT INTO educator_access (child_profile_id, caregiver_id, educator_id, reason, ask_id)
         VALUES ($1, $2, $3, $4, $5) RETURNING id`,
        [kid.id, kid.caregiver_id, req.user.id, reason, ask[0].id]);
      created.push({ accessId: made[0].id, childProfileId: kid.id });
    }
    return created;
  });

  await logAction({
    userId: req.user.id,
    action: 'child_access_requested',
    // Profile numbers only, never the name typed.
    detail: `ask_id=${ask[0].id}, parents_asked=${matched.length}${matched.length ? `, child_profile_ids=${matched.map((m) => m.childProfileId).join('|')}` : ''}`,
  });
  res.status(201).json({ id: ask[0].id, askedAt: ask[0].asked_at, message: SAME_REPLY });
}

// GET /educator/children -- the children shared with me now, and what I asked.
async function listMine(req, res) {
  // Checked first on a new device: the list names the children shared with this educator.
  const risk = await scoreIfNewDevice(req, 'list_shared_children');
  if (risk.flagged) return res.status(401).json({ error: RISK_NOTICE, code: 'SESSION_REVOKED_RISK' });
  const [{ rows: grants }, { rows: asks }] = await Promise.all([
    db.query(
      `SELECT id, child_profile_id, expires_at FROM educator_access
       WHERE educator_id = $1 AND status = 'granted' AND expires_at > now() ORDER BY decided_at DESC`, [req.user.id]),
    // An ask is "approved" while a parent's grant from it is running, and
    // "ended" once that grant was taken back or ran out. Everything else --
    // waiting, refused, or no child matched -- stays "requested", so the
    // educator cannot tell a refusal from a name that matched nobody.
    db.query(
      `SELECT a.id, a.child_name, a.reason, a.asked_at,
              CASE WHEN bool_or(ea.status = 'granted' AND ea.expires_at > now()) THEN 'approved'
                   WHEN bool_or(ea.status IN ('granted', 'revoked') AND ea.decided_at IS NOT NULL AND ea.expires_at IS NOT NULL) THEN 'ended'
                   ELSE 'requested' END AS status,
              max(ea.decided_at) FILTER (WHERE ea.expires_at IS NOT NULL) AS approved_at
       FROM educator_asks a LEFT JOIN educator_access ea ON ea.ask_id = a.id
       WHERE a.educator_id = $1 GROUP BY a.id ORDER BY a.asked_at DESC LIMIT 100`, [req.user.id]),
  ]);
  // Row-level security returns identity rows only for children with a live
  // grant, so no name can come from a pending, refused or ended request.
  const { rows: idRows } = await db.query(
    `SELECT ci.child_profile_id, ci.full_name_enc, ci.date_of_birth_enc,
            (SELECT COUNT(*)::int FROM developmental_records dr WHERE dr.child_profile_id = ci.child_profile_id) AS record_count
     FROM child_identifiers ci`);
  const visible = new Map(idRows.map((r) => [r.child_profile_id, r]));

  const children = grants.filter((g) => visible.has(g.child_profile_id)).map((g) => {
    const v = visible.get(g.child_profile_id);
    return {
      accessId: g.id,
      childProfileId: g.child_profile_id,
      fullName: decryptField(v.full_name_enc),
      age: ageText(decryptField(v.date_of_birth_enc)),
      recordCount: v.record_count,
      expiresAt: g.expires_at,
    };
  });
  // What the educator typed, and only as much status as cannot reveal
  // whether a name matched anyone (see the query above).
  res.json({
    children,
    asks: asks.map((a) => ({ id: a.id, childName: a.child_name, reason: a.reason, askedAt: a.asked_at, status: a.status, approvedAt: a.approved_at })),
  });
}

// GET /educator/children/:childProfileId/records
async function viewRecords(req, res) {
  const childProfileId = Number(req.params.childProfileId);

  const { rows: grants } = await db.query(
    "SELECT id, expires_at FROM educator_access WHERE child_profile_id = $1 AND educator_id = $2 AND status = 'granted' AND expires_at > now()",
    [childProfileId, req.user.id]);
  if (!grants[0]) {
    // The same answer whether the child exists, was never shared, or the
    // grant was refused, revoked or has run out.
    await logAction({ userId: req.user.id, action: 'access_denied_no_grant', detail: `child_profile_id=${childProfileId}, attempted=view_shared_child_records` });
    return res.status(403).json({ error: 'You do not have the parent’s permission to view this child.', code: 'NO_ACCESS_GRANT' });
  }
  const { rows: idRows } = await db.query(
    'SELECT full_name_enc, date_of_birth_enc FROM child_identifiers WHERE child_profile_id = $1', [childProfileId]);
  if (!idRows[0]) {
    return res.status(409).json({ error: 'This child’s profile has been archived by the parent.', code: 'PROFILE_ARCHIVED' });
  }
  if (!(await hasConsent(childProfileId, 'developmental_records'))) {
    await logAction({ userId: req.user.id, action: 'access_denied_no_consent', detail: `child_profile_id=${childProfileId}, scope=developmental_records, attempted=view_shared_child_records` });
    return res.status(403).json({ error: 'The parent has withdrawn consent for this child’s records.', code: 'CONSENT_REQUIRED', scope: 'developmental_records' });
  }

  // Scored BEFORE anything is read or decrypted: if this is the read that
  // crosses the limit, nothing is disclosed and the session has ended.
  const risk = await scoreAction(req, 'view_shared_child_records', childProfileId);
  if (risk.flagged) {
    await logAction({ userId: req.user.id, action: 'view_shared_child_records_refused', detail: `child_profile_id=${childProfileId}, reason=risk_flagged`, accessRequestId: risk.accessRequestId });
    return res.status(401).json({ error: RISK_NOTICE, code: 'SESSION_REVOKED_RISK' });
  }

  const { rows } = await db.query(
    `SELECT id, milestone_enc, health_indicator_enc, assessment_score_enc, progress_notes_enc, created_at
     FROM developmental_records WHERE child_profile_id = $1 ORDER BY created_at DESC`,
    [childProfileId]);
  const records = rows.map((r) => ({
    id: r.id,
    createdAt: r.created_at,
    milestone: decryptField(r.milestone_enc),
    healthIndicator: decryptField(r.health_indicator_enc),
    assessmentScore: decryptField(r.assessment_score_enc),
    progressNotes: r.progress_notes_enc ? decryptField(r.progress_notes_enc) : null,
  }));
  await logAction({ userId: req.user.id, action: 'view_shared_child_records', detail: `child_profile_id=${childProfileId}, count=${records.length}`, accessRequestId: risk.accessRequestId });
  res.json({
    child: { childProfileId, fullName: decryptField(idRows[0].full_name_enc), age: ageText(decryptField(idRows[0].date_of_birth_enc)) },
    access: { expiresAt: grants[0].expires_at },
    records,
  });
}

// ----------------------------------------------------------- the caregiver

// GET /children/access -- who has asked, who can see, and who has looked.
async function listForCaregiver(req, res) {
  const risk = await scoreIfNewDevice(req, 'list_child_access');
  if (risk.flagged) return res.status(401).json({ error: RISK_NOTICE, code: 'SESSION_REVOKED_RISK' });
  const { rows: kids } = await db.query(
    `SELECT cp.id, ci.full_name_enc FROM child_profiles cp JOIN child_identifiers ci ON ci.child_profile_id = cp.id
     WHERE cp.caregiver_id = $1`, [req.user.id]);
  const nameOf = new Map(kids.map((k) => [k.id, decryptField(k.full_name_enc)]));
  const ids = [...nameOf.keys()];
  const [{ rows }, { rows: views }] = await Promise.all([
    db.query(
      `SELECT ea.id, ea.child_profile_id, ea.reason, ea.status, ea.requested_at, ea.decided_at, ea.expires_at, ea.ended_at,
              COALESCE(u.full_name, u.email) AS educator_name, u.ecd_centre
       FROM educator_access ea JOIN users u ON u.id = ea.educator_id
       WHERE ea.caregiver_id = $1 AND ea.child_profile_id IS NOT NULL
       ORDER BY ea.requested_at DESC LIMIT 200`, [req.user.id]),
    // Every time someone other than the caregiver opened a child's records
    // (or tried and was stopped by the risk check).
    ids.length
      ? db.query(
        `SELECT ar.requested_at, ar.child_profile_id, COALESCE(u.full_name, u.email) AS viewer, r.name AS viewer_role,
                COALESCE(rs.is_flagged, FALSE) AS stopped
         FROM access_requests ar
         JOIN users u ON u.id = ar.user_id JOIN roles r ON r.id = u.role_id
         LEFT JOIN risk_scores rs ON rs.access_request_id = ar.id
         WHERE ar.action_type = 'view_shared_child_records' AND ar.child_profile_id = ANY($1)
         ORDER BY ar.requested_at DESC LIMIT 100`, [ids])
      : { rows: [] },
  ]);
  res.json({
    requests: rows.map((r) => ({
      id: r.id,
      childProfileId: r.child_profile_id,
      childName: nameOf.get(r.child_profile_id) || null,
      educatorName: r.educator_name,
      ecdCentre: r.ecd_centre,
      reason: r.reason,
      status: publicStatus(r),
      requestedAt: r.requested_at,
      decidedAt: r.decided_at,
      expiresAt: r.expires_at,
      endedAt: r.ended_at,
    })),
    views: views.map((v) => ({
      at: v.requested_at, childProfileId: v.child_profile_id, childName: nameOf.get(v.child_profile_id),
      viewer: v.viewer, viewerRole: v.viewer_role, stopped: v.stopped,
    })),
    grantDays: GRANT_DAYS,
    defaultGrantDays: DEFAULT_GRANT_DAYS,
  });
}

// The request, if it is about one of this caregiver's own children.
async function findOwnRequest(req) {
  const id = Number(req.params.accessId);
  if (!Number.isInteger(id) || id < 1 || id > 2147483647) return null;
  const { rows } = await db.query(
    `SELECT ea.* FROM educator_access ea
     JOIN child_profiles cp ON cp.id = ea.child_profile_id
     WHERE ea.id = $1 AND cp.caregiver_id = $2 AND ea.caregiver_id = $2`, [id, req.user.id]);
  return rows[0] || null;
}

// POST /children/access/:accessId/decision { decision: 'grant' | 'refuse', days }
async function decide(req, res) {
  const { decision } = req.body || {};
  if (!['grant', 'refuse'].includes(decision)) return res.status(400).json({ error: "decision must be 'grant' or 'refuse'" });
  const days = req.body.days === undefined ? DEFAULT_GRANT_DAYS : Number(req.body.days);
  if (decision === 'grant' && !GRANT_DAYS.includes(days)) {
    return res.status(400).json({ error: `days must be one of ${GRANT_DAYS.join(', ')}` });
  }
  const request = await findOwnRequest(req);
  // Same answer for "not yours" and "does not exist".
  if (!request) return res.status(404).json({ error: 'Access request not found' });
  if (request.status !== 'pending') return res.status(409).json({ error: 'This request has already been decided.', code: 'ALREADY_DECIDED' });
  // Checked BEFORE it happens on a device new to this parent: a stolen
  // parent login must not be able to hand a child's records to anyone.
  const risk = await scoreIfNewDevice(req, 'decide_child_access', request.child_profile_id);
  if (risk.flagged) return res.status(401).json({ error: RISK_NOTICE, code: 'SESSION_REVOKED_RISK' });

  let rows;
  if (decision === 'grant') {
    const { rows: who } = await db.query(
      `SELECT ci.date_of_birth_enc, cp.archived_at FROM child_identifiers ci JOIN child_profiles cp ON cp.id = ci.child_profile_id
       WHERE cp.id = $1`, [request.child_profile_id]);
    if (!who[0] || who[0].archived_at) {
      return res.status(409).json({ error: 'This child’s profile is archived. Restore it first to share it.', code: 'PROFILE_ARCHIVED' });
    }
    const dob = decryptField(who[0].date_of_birth_enc);
    if (!isEcdAge(dob)) {
      return res.status(409).json({ error: 'Educators can only be given access while a child is 3 to 6 years old.', code: 'NOT_ECD_AGE' });
    }
    // Never past the day before the 7th birthday, whatever period was chosen.
    const chosen = new Date(Date.now() + days * 86400000);
    const ageLimit = birthday(dob, ECD_END_YEARS);
    const expiresAt = ageLimit < chosen ? ageLimit : chosen;
    ({ rows } = await db.query(
      `UPDATE educator_access SET status = 'granted', decided_at = now(), decided_by = $2, expires_at = $3
       WHERE id = $1 AND status = 'pending' RETURNING status, expires_at`,
      [request.id, req.user.id, expiresAt]));
  } else {
    ({ rows } = await db.query(
      `UPDATE educator_access SET status = 'refused', decided_at = now(), decided_by = $2, ended_at = now()
       WHERE id = $1 AND status = 'pending' RETURNING status, expires_at`,
      [request.id, req.user.id]));
  }
  if (!rows[0]) return res.status(409).json({ error: 'This request has already been decided.', code: 'ALREADY_DECIDED' });

  await logAction({
    userId: req.user.id,
    action: decision === 'grant' ? 'child_access_granted' : 'child_access_refused',
    detail: `access_id=${request.id}, child_profile_id=${request.child_profile_id}, educator_id=${request.educator_id}${decision === 'grant' ? `, days=${days}` : ''}`,
  });
  res.json({ id: request.id, status: rows[0].status, expiresAt: rows[0].expires_at });
}

// POST /children/access/:accessId/revoke
async function revoke(req, res) {
  const request = await findOwnRequest(req);
  if (!request) return res.status(404).json({ error: 'Access request not found' });
  const risk = await scoreIfNewDevice(req, 'decide_child_access', request.child_profile_id);
  if (risk.flagged) return res.status(401).json({ error: RISK_NOTICE, code: 'SESSION_REVOKED_RISK' });
  const { rows } = await db.query(
    `UPDATE educator_access SET status = 'revoked', ended_at = now(), decided_by = $2
     WHERE id = $1 AND status = 'granted' RETURNING status`, [request.id, req.user.id]);
  if (!rows[0]) return res.status(409).json({ error: 'This access is not active.', code: 'NOT_ACTIVE' });
  await logAction({ userId: req.user.id, action: 'child_access_revoked', detail: `access_id=${request.id}, child_profile_id=${request.child_profile_id}, educator_id=${request.educator_id}` });
  res.json({ id: request.id, status: 'revoked' });
}

module.exports = { requestAccess, listMine, viewRecords, listForCaregiver, decide, revoke, ageText, isEcdAge };
