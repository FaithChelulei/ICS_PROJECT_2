// Anomaly-injection test (proposal 3.3.7): acts out insider-threat
// behaviour, modelled on the CERT r4.2 insider scenarios, against the
// RUNNING system, and checks both halves of the risk response:
//   detection -- did the ML model flag it, after how many actions / seconds?
//   response  -- session revoked, next request refused, queued for the
//                auditor, written to the audit log
// Normal behaviour for each role is run too, and must NOT be flagged.
//
// Run from backend/:   npm run test:anomaly   (backend on :4000, ML on :5001)
//
// Every scenario uses its own dedicated test account (created on first run,
// "+childguard-test-anomaly-..." emails, locked again at the end), so no
// scenario's activity affects another's, and real accounts are untouched.
// Flagged scenarios send the usual risk-alert email to those addresses.
//
// Night-time scenarios: in the daytime they call the same risk engine the
// API uses (real database, model, revocation, email) with a simulated 02:00
// clock. When the test is genuinely run at night (20:00-06:00, e.g. by the
// scheduled task in scripts/schedule-night-test.ps1) it switches to NIGHT
// MODE: the three night scenarios run live over HTTPS with nothing
// simulated, and the daytime scenarios are skipped -- at night even normal
// work is after-hours, so they would no longer test what they're meant to.
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });

if (process.env.TLS_CERT_FILE && !process.env.NODE_EXTRA_CA_CERTS) {
  const certPath = require('path').resolve(__dirname, '..', process.env.TLS_CERT_FILE);
  const { status } = require('child_process').spawnSync(process.execPath, [__filename], {
    stdio: 'inherit',
    env: { ...process.env, NODE_EXTRA_CA_CERTS: certPath },
  });
  process.exit(status === null ? 1 : status);
}

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const db = require('../src/config/db');
const { recordAndScore, logAccessRequest } = require('../src/services/riskEngine');
const { PRIVACY_NOTICE_VERSION } = require('../src/services/privacyNotice');

const BASE = process.env.TEST_BASE || `${process.env.TLS_CERT_FILE ? 'https' : 'http'}://localhost:4000`;
const PASS = `T3st-${crypto.randomBytes(9).toString('base64url')}`;
const inbox = (process.env.SMTP_USER || 'test@example.com').split('@');
const testEmail = (tag) => `${inbox[0]}+childguard-test-anomaly-${tag}@${inbox[1]}`;
const NOTICE = { privacyNoticeVersion: PRIVACY_NOTICE_VERSION };

async function api(p, { method = 'GET', token, device, body } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (device) headers['X-Device-Name'] = device;
  const res = await fetch(`${BASE}${p}`, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* pdf/csv */ }
  return { status: res.status, json };
}

const accounts = [];
async function account(tag, role) {
  const email = testEmail(tag);
  const hash = await bcrypt.hash(PASS, 10);
  const { rows: roleRows } = await db.query('SELECT id FROM roles WHERE name = $1', [role]);
  let { rows } = await db.query('SELECT id FROM users WHERE email = $1', [email]);
  if (rows[0]) {
    await db.query(
      `UPDATE users SET password_hash = $1, is_locked = FALSE, locked_reason = NULL,
              must_change_password = FALSE, mfa_required = FALSE WHERE id = $2`, [hash, rows[0].id]);
  } else {
    ({ rows } = await db.query(
      `INSERT INTO users (email, full_name, username, password_hash, role_id, mfa_required, must_change_password)
       VALUES ($1, $2, $3, $4, $5, FALSE, FALSE) RETURNING id`,
      [email, `Anomaly Test ${tag}`, `test.anomaly.${tag}`, hash, roleRows[0].id]));
  }
  const id = rows[0].id;
  // Start every run like a fresh working day for this account.
  await db.query("UPDATE access_requests SET requested_at = requested_at - interval '2 days' WHERE user_id = $1", [id]);
  accounts.push(id);
  return { id, email, role };
}

async function login(acct, device) {
  const r = await api('/auth/login', { method: 'POST', device, body: { identifier: acct.email, password: PASS } });
  if (!r.json || !r.json.token) throw new Error(`login failed for ${acct.email}: ${r.status}`);
  return r.json.token;
}

const flaggedBy = (r) => Boolean(r.json && (r.json.riskNotice || r.json.code === 'SESSION_REVOKED_RISK'));

// Repeats `action` until the system stops it (risk flag or download limit)
// or `max` actions have been made.
async function untilStopped(action, max) {
  const start = Date.now();
  for (let n = 1; n <= max; n++) {
    const r = await action(n);
    if (flaggedBy(r)) return { stopped: 'risk model', actions: n, seconds: (Date.now() - start) / 1000 };
    if (r.status === 429) return { stopped: 'download limit', actions: n, seconds: (Date.now() - start) / 1000 };
    if (r.status >= 400) throw new Error(`unexpected ${r.status} at action ${n}: ${JSON.stringify(r.json)}`);
  }
  return { stopped: null, actions: max, seconds: (Date.now() - start) / 1000 };
}

// Checks the automatic response for a flagged account.
async function verifyResponse(acct, token, since) {
  const me = token ? await api('/auth/me', { token }) : null;
  const { rows: flag } = await db.query(
    `SELECT rs.id, rs.combined_score, rs.role_threshold, rs.auditor_status FROM risk_scores rs
     JOIN access_requests ar ON ar.id = rs.access_request_id
     WHERE ar.user_id = $1 AND rs.is_flagged AND rs.created_at >= $2 ORDER BY rs.id DESC LIMIT 1`, [acct.id, since]);
  const { rows: log } = await db.query(
    "SELECT COUNT(*)::int AS n FROM audit_log WHERE user_id = $1 AND action = 'risk_flagged_session_revoked' AND created_at >= $2",
    [acct.id, since]);
  const { rows: sessions } = await db.query(
    "SELECT COUNT(*)::int AS n FROM sessions WHERE user_id = $1 AND revoked_reason = 'risk_flagged' AND revoked_at >= $2",
    [acct.id, since]);
  return {
    riskScoreId: flag[0] && flag[0].id,
    score: flag[0] ? Number(flag[0].combined_score) : null,
    threshold: flag[0] ? Number(flag[0].role_threshold) : null,
    sessionRevoked: sessions[0].n > 0,
    nextRequestRefused: me ? me.status === 401 && me.json && me.json.code === 'SESSION_REVOKED_RISK' : sessions[0].n > 0,
    queuedForAuditor: Boolean(flag[0] && flag[0].auditor_status === 'pending'),
    inAuditLog: log[0].n > 0,
  };
}

// Highest score this account received during the scenario (for normal runs).
async function maxScore(acct, since) {
  const { rows } = await db.query(
    `SELECT MAX(rs.combined_score) AS max, COUNT(*) FILTER (WHERE rs.is_flagged)::int AS flags FROM risk_scores rs
     JOIN access_requests ar ON ar.id = rs.access_request_id WHERE ar.user_id = $1 AND rs.created_at >= $2`, [acct.id, since]);
  return { max: rows[0].max == null ? null : Number(rows[0].max), flags: rows[0].flags };
}

async function newChild(token, device) {
  const r = await api('/children', {
    method: 'POST', token, device,
    body: { fullName: 'Anomaly Test Child', dateOfBirth: '2021-03-03', developmentalRecordsConsent: true, ...NOTICE },
  });
  if (r.status !== 201) throw new Error(`could not create child: ${r.status}`);
  return r.json.childProfileId;
}

const results = [];
function report(row) {
  results.push(row);
  const ok = row.expected === 'flag' ? row.detected : !row.detected;
  row.pass = ok && (row.expected !== 'flag' || Object.values(row.response || {}).every((v) => v !== false));
  const what = row.expected === 'flag'
    ? (row.detected ? `STOPPED by ${row.stoppedBy} after ${row.actions} action(s), ${row.seconds.toFixed(1)} s` : `NOT detected after ${row.actions} actions`)
    : (row.detected ? 'FALSE ALARM -- normal work was flagged' : `not flagged (highest score ${row.score == null ? 'n/a' : row.score.toFixed(3)})`);
  console.log(`${row.pass ? 'PASS' : 'FAIL'} - ${row.name}: ${what}`);
  if (row.response) {
    const r = row.response;
    console.log(`       response: score ${r.score == null ? 'n/a' : r.score.toFixed(3)} vs ${r.threshold ?? 'n/a'} | session revoked: ${r.sessionRevoked} | next request refused: ${r.nextRequestRefused} | queued for auditor: ${r.queuedForAuditor} | in audit log: ${r.inAuditLog}`);
  }
}

// ---------------------------------------------------------------- scenarios

async function massAccess() {
  const acct = await account('mass-access', 'Caregiver');
  const since = new Date();
  const device = 'anomaly-device-1';
  const token = await login(acct, device);
  const child = await newChild(token, device);
  const run = await untilStopped(() => api(`/children/${child}/records`, { token, device }), 40);
  report({
    name: '1. Caregiver mass-reads child records', cert: 'Scenario 2 (data theft before leaving)', expected: 'flag',
    detected: Boolean(run.stopped), stoppedBy: run.stopped, actions: run.actions + 1, seconds: run.seconds,
    response: run.stopped ? await verifyResponse(acct, token, since) : null,
  });
  return results[results.length - 1].response && results[results.length - 1].response.riskScoreId;
}

async function newDevice() {
  const acct = await account('new-device', 'Caregiver');
  const since = new Date();
  // Normal work on the usual device first (this is the owner's history)...
  const ownToken = await login(acct, 'anomaly-own-laptop');
  const child = await newChild(ownToken, 'anomaly-own-laptop');
  await api(`/children/${child}/records`, { token: ownToken, device: 'anomaly-own-laptop' });
  // ...then the same account from a browser it has never used.
  const thief = `anomaly-unknown-${crypto.randomBytes(3).toString('hex')}`;
  const token = await login(acct, thief);
  const run = await untilStopped(() => api(`/children/${child}/records`, { token, device: thief }), 5);
  report({
    name: '2. Same caregiver account used from a new device', cert: 'Stolen credentials', expected: 'flag',
    detected: Boolean(run.stopped), stoppedBy: run.stopped, actions: run.actions, seconds: run.seconds,
    response: run.stopped ? await verifyResponse(acct, token, since) : null,
  });
}

async function auditorScrape() {
  const acct = await account('auditor-scrape', 'SecurityAuditor');
  const since = new Date();
  const device = 'anomaly-device-3';
  const token = await login(acct, device);
  // Alternate reading the audit log and downloading reports, as fast as possible.
  const run = await untilStopped((n) => (n % 2
    ? api('/auditor/audit-log?limit=200', { token, device })
    : api(`/auditor/reports/audit-log?format=csv&from=2026-01-01`, { token, device })), 40);
  report({
    name: '3. Auditor scrapes the audit log and reports', cert: 'Privileged-user data theft', expected: 'flag',
    detected: Boolean(run.stopped), stoppedBy: run.stopped, actions: run.actions, seconds: run.seconds,
    response: run.stopped === 'risk model' ? await verifyResponse(acct, token, since) : null,
  });
}

async function adminBurst() {
  const acct = await account('admin-burst', 'SysAdmin');
  const since = new Date();
  const device = 'anomaly-device-4';
  const token = await login(acct, device);
  const run = await untilStopped(() => api('/admin/encryption/reencrypt', { method: 'POST', token, device, body: { password: PASS } }), 40);
  report({
    name: '4. SysAdmin fires a burst of privileged actions', cert: 'Scenario 3 (disgruntled sysadmin)', expected: 'flag',
    detected: Boolean(run.stopped), stoppedBy: run.stopped, actions: run.actions, seconds: run.seconds,
    response: run.stopped ? await verifyResponse(acct, token, since) : null,
  });
}

// Same after-hours rule as the live feature (featureComputation.js).
// ANOMALY_FORCE_NIGHT=1 runs the night-mode code path in the daytime, to
// check it works before a scheduled night run -- the server still sees
// daytime, so nothing is expected to be flagged in that dry run.
const isNightNow = () => {
  if (process.env.ANOMALY_FORCE_NIGHT === '1') return true;
  const h = new Date().getHours();
  return h < 6 || h >= 20;
};

// NIGHT MODE: real after-hours activity over HTTPS, nothing simulated.
// Each role does its everyday action until stopped (up to 3 actions).
async function nightTimeLive(n, role) {
  const acct = await account(`night-live-${role.toLowerCase()}`, role);
  const since = new Date();
  const device = 'anomaly-own-device';
  const token = await login(acct, device);
  let child = null;
  const action = {
    Caregiver: async (i) => {
      if (i === 1) {
        const r = await api('/children', {
          method: 'POST', token, device,
          body: { fullName: 'Night Test Child', dateOfBirth: '2021-03-03', developmentalRecordsConsent: true, ...NOTICE },
        });
        child = r.json && r.json.childProfileId;
        return r;
      }
      return api(`/children/${child}/records`, { token, device });
    },
    SecurityAuditor: () => api('/auditor/audit-log?limit=50', { token, device }),
    SysAdmin: () => api('/admin/encryption/reencrypt', { method: 'POST', token, device, body: { password: PASS } }),
  }[role];
  const run = await untilStopped(action, 3);
  report({
    name: `${n}. ${role} works at ${new Date().toTimeString().slice(0, 5)} (REAL night, live)`, cert: 'Scenario 1 (starts working after hours)',
    expected: 'flag', detected: Boolean(run.stopped), stoppedBy: run.stopped, actions: run.actions, seconds: run.seconds,
    response: run.stopped ? await verifyResponse(acct, token, since) : null,
  });
}

// Night-time activity, through the real risk engine with a 02:00 clock.
async function nightTime(n, role, actionType) {
  const acct = await account(`night-${role.toLowerCase()}`, role);
  const since = new Date();
  const night = new Date();
  night.setHours(2, 0, 0, 0);
  const { rows } = await db.query('INSERT INTO sessions (user_id, issued_at) VALUES ($1, $2) RETURNING id', [acct.id, night]);
  const sessionId = rows[0].id;
  const base = { userId: acct.id, pcName: 'anomaly-own-device', ipAddress: '127.0.0.1', sessionId };
  await logAccessRequest({ ...base, actionType: 'login', now: night });
  // Like the other attacks, keep going (one action every 2 simulated
  // minutes) until the system stops it -- up to 3 actions.
  const start = Date.now();
  let actions = 0;
  let flagged = false;
  while (!flagged && actions < 3) {
    actions += 1;
    const r = await recordAndScore({ ...base, role, actionType, now: new Date(night.getTime() + actions * 2 * 60000) });
    flagged = r.flagged;
  }
  report({
    name: `${n}. ${role} works at 02:00`, cert: 'Scenario 1 (starts working after hours)', expected: 'flag',
    detected: flagged, stoppedBy: flagged ? 'risk model' : null, actions, seconds: (Date.now() - start) / 1000,
    response: flagged ? await verifyResponse(acct, null, since) : null,
  });
}

async function normalCaregiver() {
  const acct = await account('normal-caregiver', 'Caregiver');
  const since = new Date();
  const device = 'anomaly-device-8';
  const token = await login(acct, device);
  const child = await newChild(token, device);
  await api(`/children/${child}/records`, { token, device });
  const sub = await api(`/children/${child}/records`, {
    method: 'POST', token, device, body: { milestone: 'First words', healthIndicator: 'Healthy', assessmentScore: 7 },
  });
  const s = await maxScore(acct, since);
  report({ name: '8. Normal caregiver: register, view, add a record', expected: 'none', detected: s.flags > 0 || flaggedBy(sub), score: s.max });
}

async function normalAuditor(flagToReview) {
  const acct = await account('normal-auditor', 'SecurityAuditor');
  const since = new Date();
  const device = 'anomaly-device-9';
  const token = await login(acct, device);
  await api('/auditor/flagged-sessions', { token, device });
  await api('/auditor/audit-log?limit=50', { token, device });
  if (flagToReview) {
    await api(`/auditor/flagged-sessions/${flagToReview}/review`, { method: 'POST', token, device, body: { status: 'reviewing' } });
  }
  const exp = await api('/auditor/reports/flagged-sessions?format=pdf', { token, device });
  const s = await maxScore(acct, since);
  report({ name: '9. Normal auditor: triage a flag, read the log, one report', expected: 'none', detected: s.flags > 0 || flaggedBy(exp), score: s.max });
}

async function normalAdmin() {
  const acct = await account('normal-admin', 'SysAdmin');
  const since = new Date();
  const device = 'anomaly-device-10';
  const token = await login(acct, device);
  await api('/admin/registration-requests', { token, device });
  await api('/admin/encryption/status', { token, device });
  const re = await api('/admin/encryption/reencrypt', { method: 'POST', token, device, body: { password: PASS } });
  await api('/admin/retention/status', { token, device });
  const s = await maxScore(acct, since);
  report({ name: '10. Normal SysAdmin: check status, one re-encryption', expected: 'none', detected: s.flags > 0 || flaggedBy(re), score: s.max });
}

async function main() {
  for (let ok = 0, i = 0; ok < 3 && i < 40; i++) {
    ok = (await fetch(`${BASE}/health`).then((r) => r.ok).catch(() => false)) ? ok + 1 : 0;
    await new Promise((r) => setTimeout(r, 500));
  }

  if (isNightNow()) {
    console.log(`NIGHT MODE (${new Date().toString().slice(0, 24)}): real after-hours activity over HTTPS, nothing simulated.`);
    console.log('Daytime scenarios are skipped -- at night every action is after-hours.\n');
    console.log('=== Night-time attacks (each must be STOPPED) ===');
    await nightTimeLive(5, 'Caregiver');
    await nightTimeLive(6, 'SecurityAuditor');
    await nightTimeLive(7, 'SysAdmin');
  } else {
    console.log('=== Attacks (each must be STOPPED) ===');
    const flagId = await massAccess();
    await newDevice();
    await auditorScrape();
    await adminBurst();
    await nightTime(5, 'Caregiver', 'view_own_child_records');
    await nightTime(6, 'SecurityAuditor', 'view_audit_log');
    await nightTime(7, 'SysAdmin', 'reencrypt_data');

    console.log('\n=== Normal work (must NOT be flagged) ===');
    await normalCaregiver();
    await normalAuditor(flagId);
    await normalAdmin();
  }

  const attacks = results.filter((r) => r.expected === 'flag');
  const normal = results.filter((r) => r.expected === 'none');
  const caught = attacks.filter((r) => r.detected).length;
  const falseAlarms = normal.filter((r) => r.detected).length;
  console.log('\n=== SUMMARY ===');
  console.log(`Attacks stopped:      ${caught}/${attacks.length}`);
  if (normal.length) console.log(`False alarms:         ${falseAlarms}/${normal.length} normal sessions`);
  console.log(`Full response worked: ${attacks.filter((r) => r.response && Object.values(r.response).every((v) => v !== false)).length}/${attacks.filter((r) => r.stoppedBy === 'risk model').length} model-flagged attacks (revoked, refused, queued, logged)`);
  console.log(`${results.every((r) => r.pass) ? 'RESULT: PASS' : 'RESULT: FAIL'} -- ${results.filter((r) => r.pass).length}/${results.length} scenarios behaved as expected.`);

  const outDir = path.join(__dirname, 'results');
  fs.mkdirSync(outDir, { recursive: true });
  const mode = isNightNow() ? 'night' : 'day';
  const outFile = path.join(outDir, `anomaly_${mode}_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.json`);
  fs.writeFileSync(outFile, JSON.stringify({ ranAt: new Date().toISOString(), localTime: new Date().toString(), mode, results }, null, 2));
  console.log(`Saved: ${path.relative(path.join(__dirname, '..'), outFile)}`);
  return results.every((r) => r.pass) ? 0 : 1;
}

main()
  .then(async (code) => code)
  .catch((err) => {
    console.error('\nTest could not complete:', err.message, err.cause ? `(${err.cause.code || err.cause.message})` : '');
    return 1;
  })
  .then(async (code) => {
    if (accounts.length) {
      await db.query(
        "UPDATE users SET is_locked = TRUE, locked_reason = 'automated test account (locked between runs)' WHERE id = ANY($1)", [accounts]);
    }
    await db.pool.end();
    process.exit(code);
  });
