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
const { refreshWeek, localDate } = require('../src/services/weeklyReview');
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

// Re-encryption needs a second admin's approval now: an attempt without one
// is refused (409) but still logged and scored like the action, so for the
// burst and night scenarios it counts as one more privileged action.
const attempt = (r) => (r.status === 409 && r.json && r.json.code === 'APPROVAL_REQUIRED' ? { ...r, status: 200 } : r);

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
    const extra = Object.entries(r).filter(([k]) => !['score', 'threshold', 'riskScoreId'].includes(k)).map(([k, v]) => `${k}: ${v}`).join(' | ');
    console.log(`       response: score ${r.score == null ? 'n/a' : r.score.toFixed(3)} vs ${r.threshold ?? 'n/a'} | ${extra}`);
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
  const run = await untilStopped(() => api('/admin/encryption/reencrypt', { method: 'POST', token, device, body: { password: PASS } }).then(attempt), 40);
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
    SysAdmin: () => api('/admin/encryption/reencrypt', { method: 'POST', token, device, body: { password: PASS } }).then(attempt),
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
  // Caregivers' after-hours feature uses their own usual hours (activity at
  // this time on 3+ days in the last 30, featureComputation.js). Every run of
  // this test adds 02:00 activity, so after a few runs 02:00 became "usual"
  // for this test account. Move its earlier activity out of that window so
  // each run is a person with no night-time history, as the scenario means.
  await db.query("UPDATE access_requests SET requested_at = requested_at - interval '60 days' WHERE user_id = $1", [acct.id]);
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
  // Re-encryption needs a second admin (two-person approval): a normal
  // admin asks for it, with a reason.
  const re = await api('/admin/approvals', { method: 'POST', token, device,
    body: { action: 'reencrypt_data', reason: 'Routine key rotation this month', password: PASS } });
  await api('/admin/retention/status', { token, device });
  const s = await maxScore(acct, since);
  report({ name: '10. Normal SysAdmin: check status, ask for a re-encryption', expected: 'none', detected: s.flags > 0 || flaggedBy(re), score: s.max });
}


// ------------------------------------------------- Educator (SOFIA 3.1)
// An educator only reads children a parent has shared with them. These set
// the sharing up the real way: the parent registers a child (ECD age), the
// educator asks for that child by name, and the parent grants the request.
async function sharedChild(teacher, teacherToken, teacherDevice, tag) {
  const parent = await account(`${tag}-parent`, 'Caregiver');
  const pDevice = `anomaly-${tag}-parent`;
  const pToken = await login(parent, pDevice);
  const letters = (n) => Array.from({ length: n }, () => 'abcdefghijklmnopqrstuvwxyz'[Math.floor(Math.random() * 26)]).join('');
  const childName = `Pupil ${letters(8)} ${letters(6)}`;
  const dob = new Date(Date.now() - 4 * 365.25 * 86400000).toISOString().slice(0, 10);
  const made = await api('/children', { method: 'POST', token: pToken, device: pDevice,
    body: { fullName: childName, dateOfBirth: dob, developmentalRecordsConsent: true, ...NOTICE } });
  if (made.status !== 201) throw new Error(`could not create child: ${made.status}`);
  const child = made.json.childProfileId;
  await api(`/children/${child}/records`, { method: 'POST', token: pToken, device: pDevice,
    body: { milestone: 'Counts to ten', healthIndicator: 'Healthy', assessmentScore: 7 } });
  const asked = await api('/educator/access-requests', { method: 'POST', token: teacherToken, device: teacherDevice,
    body: { childName, reason: 'I am this child\'s educator at the centre' } });
  const inbox = await api('/children/access', { token: pToken, device: pDevice });
  const row = inbox.json && inbox.json.requests.find((r) => r.status === 'pending' && r.childProfileId === child);
  const granted = row && await api(`/children/access/${row.id}/decision`, { method: 'POST', token: pToken, device: pDevice,
    body: { decision: 'grant', days: 30 } });
  if (!granted || granted.status !== 200) throw new Error(`could not share a child with the educator: ${asked.status}/${granted && granted.status}`);
  return child;
}

async function teacherMassReading() {
  const acct = await account('teacher-mass', 'Educator');
  const since = new Date();
  const device = 'anomaly-teacher-mass';
  const token = await login(acct, device);
  const child = await sharedChild(acct, token, device, 'teacher-mass');
  const run = await untilStopped(() => api(`/educator/children/${child}/records`, { token, device }), 40);
  report({
    name: '14. Educator reads a shared child\'s records over and over', cert: 'Scenario 2 (data theft before leaving)', expected: 'flag',
    detected: Boolean(run.stopped), stoppedBy: run.stopped, actions: run.actions, seconds: run.seconds,
    response: run.stopped ? await verifyResponse(acct, token, since) : null,
  });
}

async function teacherNewDevice() {
  const acct = await account('teacher-stolen', 'Educator');
  const since = new Date();
  const own = 'anomaly-teacher-own-laptop';
  const ownToken = await login(acct, own);
  const child = await sharedChild(acct, ownToken, own, 'teacher-stolen');
  await api(`/educator/children/${child}/records`, { token: ownToken, device: own });
  const thief = `anomaly-unknown-${crypto.randomBytes(3).toString('hex')}`;
  const token = await login(acct, thief);
  const run = await untilStopped(() => api(`/educator/children/${child}/records`, { token, device: thief }), 5);
  report({
    name: '15. Educator account used from a new device', cert: 'Stolen credentials', expected: 'flag',
    detected: Boolean(run.stopped), stoppedBy: run.stopped, actions: run.actions, seconds: run.seconds,
    response: run.stopped ? await verifyResponse(acct, token, since) : null,
  });
}

async function normalTeacher() {
  const acct = await account('teacher-normal', 'Educator');
  const since = new Date();
  const device = 'anomaly-teacher-normal';
  const token = await login(acct, device);
  const child = await sharedChild(acct, token, device, 'teacher-normal');
  let flagged = false;
  for (let i = 0; i < 3; i++) flagged = flaggedBy(await api(`/educator/children/${child}/records`, { token, device })) || flagged;
  const s = await maxScore(acct, since);
  report({ name: '16. Normal educator: asks, is granted, reads a child\'s records', expected: 'none', detected: s.flags > 0 || flagged, score: s.max });
}

// ---------------------------------------------------------------- layer 2
// The weekly review needs weeks of history. It is replayed through the REAL
// risk engine with a replayed clock (like nightTime above): every past day's
// actions are logged, their features computed by featureComputation.js and
// scored by the live models, exactly as if they had happened then. Earlier
// runs' activity is first moved 400 days back, out of the 30-day window.
const DAY_MS = 24 * 60 * 60 * 1000;
function mondayOf(d) {
  const x = new Date(d);
  x.setHours(0, 0, 0, 0);
  x.setDate(x.getDate() - ((x.getDay() + 6) % 7));
  return x;
}

async function replay(acct, role, actionType, { days, perDay, hour, minute = 0, gapMinutes, device, isNight = () => false }) {
  await db.query("UPDATE access_requests SET requested_at = requested_at - interval '400 days' WHERE user_id = $1", [acct.id]);
  let layer1Flags = 0;
  for (const day of days) {
    const t0 = new Date(day);
    if (isNight(day)) t0.setHours(23, 10, 0, 0); else t0.setHours(hour, minute, 0, 0);
    if (t0 > new Date()) continue;
    const { rows } = await db.query('INSERT INTO sessions (user_id, issued_at) VALUES ($1, $2) RETURNING id', [acct.id, t0]);
    const base = { userId: acct.id, pcName: device, ipAddress: '127.0.0.1', sessionId: rows[0].id };
    await logAccessRequest({ ...base, actionType: 'login', now: t0 });
    for (let i = 1; i <= perDay(day); i++) {
      const r = await recordAndScore({ ...base, role, actionType, now: new Date(t0.getTime() + i * gapMinutes * 60000) });
      if (r.flagged) { layer1Flags += 1; break; }
    }
  }
  return layer1Flags;
}

function daysFrom(start, end) {
  const out = [];
  for (let t = new Date(start); t <= end; t = new Date(t.getTime() + DAY_MS)) out.push(new Date(t));
  return out;
}

async function weeklyScenarios() {
  // The scenarios use the LAST COMPLETE week (Monday to Sunday), so they
  // test the same thing whatever day they run: on a Monday the current week
  // has hardly begun, and "all week" would be a few hours.
  const monday = new Date(mondayOf(new Date()).getTime() - 7 * DAY_MS);
  const sunday = new Date(monday.getTime() + 6 * DAY_MS);
  const history = daysFrom(new Date(monday.getTime() - 35 * DAY_MS), new Date(monday.getTime() - DAY_MS));
  const thisWeek = daysFrom(monday, sunday);
  const inWeek = (d) => d >= monday;

  // 11. Quiet insider: same device, same hours, never fast enough to be
  //     signed out -- but three times their own usual reading, all week.
  const quiet = await account('weekly-quiet-insider', 'Caregiver');
  const quietL1 = await replay(quiet, 'Caregiver', 'view_own_child_records',
    { days: [...history, ...thisWeek], perDay: (d) => (inWeek(d) ? 9 : 3), hour: 9, gapMinutes: 6, device: 'anomaly-weekly-quiet' });
  // 12. The same person's normal habits, with no change this week.
  const steady = await account('weekly-normal-caregiver', 'Caregiver');
  const steadyL1 = await replay(steady, 'Caregiver', 'view_own_child_records',
    { days: [...history, ...thisWeek], perDay: () => 3, hour: 10, gapMinutes: 6, device: 'anomaly-weekly-steady' });
  // 13. A System Administrator who works by day, then once at 23:10 this week.
  const admin = await account('weekly-night-admin', 'SysAdmin');
  const firstThisWeek = thisWeek[0];
  await replay(admin, 'SysAdmin', 'approve_registration',
    { days: [...history, ...thisWeek], perDay: () => 2, hour: 11, gapMinutes: 5, device: 'anomaly-weekly-admin',
      isNight: (d) => d.getTime() === firstThisWeek.getTime() });

  // 17. A teacher who reads about three times their own usual every day this
  //     week: on their usual laptop, in school hours, never fast enough to be
  //     signed out.
  const teacher = await account('weekly-quiet-teacher', 'Educator');
  const teacherL1 = await replay(teacher, 'Educator', 'view_shared_child_records',
    { days: [...history, ...thisWeek], perDay: (d) => (inWeek(d) ? 9 : 3), hour: 10, gapMinutes: 6, device: 'anomaly-weekly-teacher' });

  // An auditor re-scores the week, as the hourly job would.
  const auditor = await account('weekly-auditor', 'SecurityAuditor');
  const token = await login(auditor, 'anomaly-weekly-auditor');
  // Score that week with the same code the hourly job runs (the page's
  // "Re-score" button only re-scores the current week), then read it as the
  // auditor's page does.
  const refreshed = await refreshWeek(monday);
  const list = await api(`/auditor/weekly-review?week=${localDate(monday)}`, { token, device: 'anomaly-weekly-auditor' });
  if (!refreshed.ok || !list.json) throw new Error(`weekly review unavailable: ${refreshed.error || list.status}`);
  const row = (a) => list.json.people.find((p) => p.user_id === a.id);
  const caregivers = list.json.people.filter((p) => p.role === 'Caregiver');

  const q = row(quiet);
  report({
    name: '11. Quiet insider: 3x their own usual reading all week, same device and hours (weekly review)',
    cert: 'Scenario 2 (gradual data theft)', expected: 'flag', detected: Boolean(q && q.needs_review),
    stoppedBy: q && q.needs_review ? 'weekly review' : null, actions: thisWeek.length * 9, seconds: 0,
    response: q ? {
      score: Number(q.score), threshold: 1,
      listedAboveLine: Boolean(q.above_limit),
      rankedFirstAmongCaregivers: caregivers.length > 0 && caregivers[0].user_id === quiet.id,
      reasonShown: q.reasons.length > 0,
      neverSignedOut: quietL1 === 0,
    } : null,
  });
  const st = row(steady);
  report({ name: '12. Normal caregiver, usual habits all week (weekly review)', expected: 'none',
    detected: Boolean(st && st.needs_review) || steadyL1 > 0, score: st ? Number(st.score) : null });
  const ad = row(admin);
  report({
    name: '13. System Administrator works once at 23:10 this week (always-review rule)', expected: 'flag',
    detected: Boolean(ad && ad.rule_flags.some((f) => f.code === 'privileged_night')),
    stoppedBy: 'always-review rule', actions: 1, seconds: 0,
    response: ad ? { score: Number(ad.score), threshold: 1, listed: Boolean(ad.needs_review), ruleShown: ad.rule_flags.length > 0 } : null,
  });
  const t = row(teacher);
  report({
    name: '17. Quiet educator: 3x their own usual reading all week, same device and hours (weekly review)',
    cert: 'Scenario 2 (gradual data theft)', expected: 'flag', detected: Boolean(t && t.needs_review),
    stoppedBy: t && t.needs_review ? 'weekly review' : null, actions: thisWeek.length * 9, seconds: 0,
    response: t ? {
      score: Number(t.score), threshold: 1,
      listedAsEducator: t.role === 'Educator',
      listedAboveLine: Boolean(t.above_limit),
      reasonShown: t.reasons.length > 0,
      neverSignedOut: teacherL1 === 0,
    } : null,
  });
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
    await teacherMassReading();
    await teacherNewDevice();

    console.log('\n=== Normal work (must NOT be flagged) ===');
    await normalCaregiver();
    await normalAuditor(flagId);
    await normalAdmin();
    await normalTeacher();

    console.log('\n=== Weekly review, layer 2 (replayed weeks through the live risk engine) ===');
    await weeklyScenarios();
  }

  const attacks = results.filter((r) => r.expected === 'flag');
  const normal = results.filter((r) => r.expected === 'none');
  const caught = attacks.filter((r) => r.detected).length;
  const falseAlarms = normal.filter((r) => r.detected).length;
  console.log('\n=== SUMMARY ===');
  console.log(`Attacks stopped:      ${caught}/${attacks.length}`);
  if (normal.length) console.log(`False alarms:         ${falseAlarms}/${normal.length} normal sessions`);
  const byModel = attacks.filter((r) => r.stoppedBy === 'risk model');
  console.log(`Full response worked: ${byModel.filter((r) => r.response && Object.values(r.response).every((v) => v !== false)).length}/${byModel.length} model-flagged attacks (revoked, refused, queued, logged)`);
  const weekly = results.filter((r) => /weekly review|always-review/.test(r.name));
  if (weekly.length) console.log(`Weekly review (layer 2): ${weekly.filter((r) => r.pass).length}/${weekly.length} scenarios as expected`);
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
