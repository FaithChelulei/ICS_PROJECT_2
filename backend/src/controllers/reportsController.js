// Downloadable reports for the Security Auditor, as CSV (for analysis in
// Excel/Sheets) or PDF (for printing / attaching). Three reports:
//   audit-log         every logged action, with its risk score if it had one
//   flagged-sessions  every ML risk flag and how it was resolved
//   consent-activity  every consent grant/revoke + every request refused
//                     for missing consent (child profile IDs only -- no names)
//
// GET /auditor/reports/:report?format=csv|pdf&from=YYYY-MM-DD&to=YYYY-MM-DD
//     (audit-log also takes action= and q=, same as the Audit Log screen)
//
// Exporting is itself a sensitive bulk read, so every export is written to
// the audit log and goes through the risk engine BEFORE the file is sent: a
// flagged export is refused and the session revoked, rather than handing
// over the data and logging out afterwards.
const db = require('../config/db');
const { logAction } = require('../utils/auditLog');
const { scoreAction, RISK_NOTICE } = require('../services/actionScoring');
const { toCsv, writePdf } = require('../utils/reportFormats');

// Upper bound per export -- enough for this system's volume, and stops one
// request from pulling an unbounded table into memory.
const MAX_ROWS = 10000;

const pad = (n) => String(n).padStart(2, '0');
function fmtTime(value) {
  if (!value) return '';
  const d = new Date(value);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}
const fmtScore = (v) => (v == null ? '' : Number(v).toFixed(3));
const titleCase = (s) => (s ? s.replace(/_/g, ' ').replace(/^\w/, (c) => c.toUpperCase()) : '');

// Adds "<column> >= from" / "< to + 1 day" (the `to` day is inclusive).
function dateClauses(column, { from, to }, params, clauses) {
  if (from) {
    params.push(from);
    clauses.push(`${column} >= $${params.length}::date`);
  }
  if (to) {
    params.push(to);
    clauses.push(`${column} < $${params.length}::date + 1`);
  }
}
// s.43 status of one flagged session: decided (and how fast), still open
// against the 72-hour window, or not a breach candidate at all.
function breachText(r) {
  const hoursSince = (to) => ((new Date(to) - new Date(r.created_at)) / 3600000).toFixed(0);
  if (r.breach_decision) {
    const label = r.breach_decision === 'notified_commissioner' ? 'Commissioner notified' : 'No real risk of harm';
    return `${label} (${hoursSince(r.breach_decided_at)} h)`;
  }
  if (r.auditor_status === 'escalated' || r.owner_response === 'not_me') {
    const open = hoursSince(new Date());
    return open > 72 ? `OVERDUE - undecided after ${open} h` : `Open - ${open} h of 72`;
  }
  return '';
}

const whereOf = (clauses) => (clauses.length ? `WHERE ${clauses.join(' AND ')}` : '');

const REPORTS = {
  'audit-log': {
    title: 'Audit Log Report',
    columns: [
      { key: 'time', label: 'Time', width: 11 },
      { key: 'user', label: 'User', width: 19 },
      { key: 'role', label: 'Role', width: 9 },
      { key: 'action', label: 'Action', width: 20 },
      { key: 'detail', label: 'Detail', width: 27 },
      { key: 'risk', label: 'Risk score', width: 6 },
      { key: 'outcome', label: 'Outcome', width: 8 },
    ],
    async load(filters) {
      const params = [];
      const clauses = [];
      dateClauses('al.created_at', filters, params, clauses);
      if (filters.action) {
        params.push(filters.action);
        clauses.push(`al.action = $${params.length}`);
      }
      if (filters.q) {
        params.push(`%${filters.q}%`);
        clauses.push(`(u.email ILIKE $${params.length} OR al.action ILIKE $${params.length} OR al.detail ILIKE $${params.length})`);
      }
      params.push(MAX_ROWS + 1);
      const { rows } = await db.query(
        `SELECT al.created_at, al.action, al.detail, u.email, r.name AS role, rs.combined_score, rs.is_flagged
         FROM audit_log al
         LEFT JOIN users u ON u.id = al.user_id
         LEFT JOIN roles r ON r.id = u.role_id
         LEFT JOIN risk_scores rs ON rs.access_request_id = al.access_request_id
         ${whereOf(clauses)}
         ORDER BY al.created_at DESC, al.id DESC
         LIMIT $${params.length}`,
        params
      );
      return rows.map((r) => ({
        time: fmtTime(r.created_at),
        user: r.email || 'system',
        role: r.role || '',
        action: r.action,
        detail: r.detail || '',
        risk: fmtScore(r.combined_score),
        outcome: r.is_flagged === true ? 'Flagged' : r.is_flagged === false ? 'Allowed' : 'Unscored',
      }));
    },
  },

  'flagged-sessions': {
    title: 'Flagged Sessions Report',
    columns: [
      { key: 'time', label: 'Flagged at', width: 11 },
      { key: 'user', label: 'User', width: 18 },
      { key: 'role', label: 'Role', width: 9 },
      { key: 'action', label: 'Action', width: 15 },
      { key: 'device', label: 'Device', width: 11 },
      { key: 'ip', label: 'IP address', width: 9 },
      { key: 'score', label: 'Risk score', width: 6 },
      { key: 'threshold', label: 'Threshold', width: 7 },
      { key: 'owner', label: 'Owner response', width: 9 },
      { key: 'auditor', label: 'Auditor status', width: 8 },
      { key: 'breach', label: 'Breach decision (s.43)', width: 12 },
    ],
    async load(filters) {
      const params = [];
      const clauses = ['rs.is_flagged = TRUE'];
      dateClauses('rs.created_at', filters, params, clauses);
      params.push(MAX_ROWS + 1);
      const { rows } = await db.query(
        `SELECT rs.created_at, rs.combined_score, rs.role_threshold, rs.owner_response, rs.auditor_status,
                rs.breach_decision, rs.breach_decided_at,
                ar.action_type, ar.pc_name, ar.ip_address, u.email, r.name AS role
         FROM risk_scores rs
         JOIN access_requests ar ON ar.id = rs.access_request_id
         JOIN users u ON u.id = ar.user_id
         JOIN roles r ON r.id = u.role_id
         ${whereOf(clauses)}
         ORDER BY rs.created_at DESC, rs.id DESC
         LIMIT $${params.length}`,
        params
      );
      const OWNER = { pending: 'No response yet', confirmed_benign: 'This was me', not_me: 'This was NOT me' };
      return rows.map((r) => ({
        time: fmtTime(r.created_at),
        user: r.email,
        role: r.role,
        action: r.action_type,
        device: r.pc_name || 'unknown',
        ip: r.ip_address || '',
        score: fmtScore(r.combined_score),
        threshold: fmtScore(r.role_threshold),
        owner: OWNER[r.owner_response] || r.owner_response,
        auditor: titleCase(r.auditor_status),
        breach: breachText(r),
      }));
    },
  },

  'consent-activity': {
    title: 'Consent Activity Report',
    columns: [
      { key: 'time', label: 'Time', width: 12 },
      { key: 'caregiver', label: 'Caregiver', width: 22 },
      { key: 'child', label: 'Child profile ID', width: 9 },
      { key: 'event', label: 'Event', width: 11 },
      { key: 'scope', label: 'Scope', width: 18 },
      { key: 'detail', label: 'Attempted action', width: 20 },
    ],
    async load(filters) {
      // Grants/revokes come from consent_records; refusals from the audit
      // log entries written by the consent check (childRecordsController).
      const params = [];
      const clauses = [];
      dateClauses('t.at', filters, params, clauses);
      params.push(MAX_ROWS + 1);
      const { rows } = await db.query(
        `SELECT * FROM (
           SELECT cr.recorded_at AS at, u.email, cr.child_profile_id,
                  CASE WHEN cr.consent_given THEN 'Granted' ELSE 'Revoked' END AS event,
                  cr.scope, NULL AS detail, cr.id AS tiebreak
           FROM consent_records cr
           LEFT JOIN users u ON u.id = cr.caregiver_id
           UNION ALL
           SELECT al.created_at, u.email,
                  substring(al.detail from 'child_profile_id=([0-9]+)')::int,
                  'Access refused',
                  substring(al.detail from 'scope=([a-z_]+)'),
                  substring(al.detail from 'attempted=([a-z_]+)'),
                  al.id
           FROM audit_log al
           LEFT JOIN users u ON u.id = al.user_id
           WHERE al.action = 'access_denied_no_consent'
         ) t
         ${whereOf(clauses)}
         ORDER BY t.at DESC, t.tiebreak DESC
         LIMIT $${params.length}`,
        params
      );
      return rows.map((r) => ({
        time: fmtTime(r.at),
        caregiver: r.email || '',
        child: r.child_profile_id == null ? '' : String(r.child_profile_id),
        event: r.event,
        scope: titleCase(r.scope),
        detail: r.detail || '',
      }));
    },
  },
};

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

async function downloadReport(req, res) {
  const report = REPORTS[req.params.report];
  if (!report) {
    return res.status(404).json({ error: `Unknown report. Available: ${Object.keys(REPORTS).join(', ')}` });
  }
  const format = req.query.format || 'csv';
  if (!['csv', 'pdf'].includes(format)) {
    return res.status(400).json({ error: 'format must be csv or pdf' });
  }
  const { from, to } = req.query;
  for (const [name, value] of [['from', from], ['to', to]]) {
    if (value && (!DATE_RE.test(value) || Number.isNaN(new Date(value).getTime()))) {
      return res.status(400).json({ error: `${name} must be a date in YYYY-MM-DD format` });
    }
  }
  if (from && to && from > to) {
    return res.status(400).json({ error: '"from" must be on or before "to"' });
  }
  const filters = { from, to, action: req.query.action, q: req.query.q };

  // Scored before anything is sent -- see header comment.
  const risk = await scoreAction(req, 'export_report');
  if (risk.flagged) {
    return res.status(401).json({ error: RISK_NOTICE, code: 'SESSION_REVOKED_RISK' });
  }

  const loaded = await report.load(filters);
  const truncated = loaded.length > MAX_ROWS;
  const rows = truncated ? loaded.slice(0, MAX_ROWS) : loaded;

  const filterText = [
    filters.action && `action = ${filters.action}`,
    filters.q && `search "${filters.q}"`,
  ].filter(Boolean).join(', ');
  await logAction({
    userId: req.user.id,
    action: 'export_report',
    detail: `report=${req.params.report}, format=${format}, rows=${rows.length}, from=${from || 'start'}, to=${to || 'now'}${filterText ? `, filters: ${filterText}` : ''}`,
  });

  const now = new Date();
  const stamp = fmtTime(now).slice(0, 10);
  const filename = `${req.params.report}_${from || 'start'}_to_${to || stamp}.${format}`;
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.setHeader('X-Report-Rows', String(rows.length));
  if (truncated) res.setHeader('X-Report-Truncated', String(MAX_ROWS));

  if (format === 'csv') {
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    return res.send(toCsv({ columns: report.columns, rows }));
  }

  res.setHeader('Content-Type', 'application/pdf');
  writePdf({
    title: report.title,
    columns: report.columns,
    rows,
    meta: [
      'ChildGuard - Child Data Security System',
      `Period: ${from || 'start of records'} to ${to || stamp}${filterText ? `   |   Filters: ${filterText}` : ''}`,
      `Generated ${fmtTime(now)} by ${req.user.email} (Security Auditor)`,
      `${rows.length} record(s)${truncated ? ` - truncated to the most recent ${MAX_ROWS}; narrow the date range for the rest` : ''}`,
    ],
  }, res);
}

module.exports = { downloadReport, REPORT_NAMES: Object.keys(REPORTS) };
