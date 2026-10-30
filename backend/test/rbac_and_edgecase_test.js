// End-to-end API checks against the RUNNING backend + ML service.
// Run from backend/:   npm run test:api   (backend on :4000, ML on :5001)
//
// Non-destructive: it never deletes or edits your real accounts or data.
// It uses three dedicated test accounts (created on first run, reused
// after) with MFA off and a fresh random password each run, and LOCKS them
// again at the end so they can't be signed into between runs. Their
// activity (one deliberately flagged session, one test child) stays in the
// audit trail under the "childguard.test" names -- the audit log is
// append-only by design, so nothing is cleaned up from it.
// Email: at most one risk-alert email, to a +test address of the SMTP inbox.
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });

// The backend serves HTTPS with a local self-signed certificate. Node reads
// NODE_EXTRA_CA_CERTS only at start-up, so re-launch this script once with
// it pointing at that certificate (works whether or not cert:trust was run).
if (process.env.TLS_CERT_FILE && !process.env.NODE_EXTRA_CA_CERTS) {
  const certPath = require('path').resolve(__dirname, '..', process.env.TLS_CERT_FILE);
  const { status } = require('child_process').spawnSync(process.execPath, [__filename], {
    stdio: 'inherit',
    env: { ...process.env, NODE_EXTRA_CA_CERTS: certPath },
  });
  process.exit(status === null ? 1 : status);
}

const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const db = require('../src/config/db');
const { signRiskResponseToken } = require('../src/utils/riskResponseToken');
const { PRIVACY_NOTICE_VERSION } = require('../src/services/privacyNotice');

const BASE = `${process.env.TLS_CERT_FILE ? 'https' : 'http'}://localhost:4000`;
const PASS = `T3st-${crypto.randomBytes(9).toString('base64url')}`;
const inbox = (process.env.SMTP_USER || 'test@example.com').split('@');
const testEmail = (tag) => `${inbox[0]}+childguard-test-${tag}@${inbox[1]}`;

const ACCOUNTS = {
  cg: { tag: 'caregiver', role: 'Caregiver', username: 'test.caregiver', name: 'Test Caregiver' },
  // Separate caregiver for the archive/retention checks, so their extra
  // data actions don't push the main test caregiver's risk score over the
  // threshold mid-run (which would correctly revoke its session).
  cg2: { tag: 'caregiver2', role: 'Caregiver', username: 'test.caregiver2', name: 'Test Caregiver Two' },
  au: { tag: 'auditor', role: 'SecurityAuditor', username: 'test.auditor', name: 'Test Auditor' },
  ad: { tag: 'admin', role: 'SysAdmin', username: 'test.admin', name: 'Test Admin' },
};

const results = [];
function record(name, ok, detail) {
  results.push({ name, ok, detail });
  console.log(`${ok ? 'PASS' : 'FAIL'} - ${name}${detail ? ' :: ' + detail : ''}`);
}

async function ensureTestAccount(a) {
  const email = testEmail(a.tag);
  const hash = await bcrypt.hash(PASS, 10);
  const { rows: roleRows } = await db.query('SELECT id FROM roles WHERE name = $1', [a.role]);
  const { rows } = await db.query('SELECT id FROM users WHERE email = $1', [email]);
  if (rows[0]) {
    await db.query(
      `UPDATE users SET password_hash = $1, is_locked = FALSE, locked_reason = NULL,
              must_change_password = FALSE, mfa_required = FALSE WHERE id = $2`,
      [hash, rows[0].id]
    );
    return { ...a, email, id: rows[0].id };
  }
  const { rows: ins } = await db.query(
    `INSERT INTO users (email, full_name, username, password_hash, role_id, mfa_required, must_change_password)
     VALUES ($1, $2, $3, $4, $5, FALSE, FALSE) RETURNING id`,
    [email, a.name, a.username, hash, roleRows[0].id]
  );
  return { ...a, email, id: ins[0].id };
}

// The risk features are day- and hour-based (files/events today, devices
// used today), so a second run on the same day would start with the first
// run's activity -- including its deliberate new-device login -- and the
// "normal first action is NOT flagged" check would correctly fail. Ageing
// the TEST accounts' earlier activity by two days makes every run start
// like a fresh working day while keeping device A in their history (so
// it's still "known"). Never touches real accounts or the audit log.
async function ageTestActivity(ids) {
  await db.query(
    "UPDATE access_requests SET requested_at = requested_at - interval '2 days' WHERE user_id = ANY($1)",
    [ids]
  );
}

async function lockTestAccounts() {
  await db.query(
    "UPDATE users SET is_locked = TRUE, locked_reason = 'automated test account (locked between runs)' WHERE email LIKE $1",
    [`${inbox[0]}+childguard-test-%@${inbox[1]}`]
  );
}

async function api(path, { method = 'GET', token, device, body } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (device) headers['X-Device-Name'] = device;
  const res = await fetch(`${BASE}${path}`, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* html or empty */ }
  return { status: res.status, json, text };
}

async function login(identifier, device) {
  const r = await api('/auth/login', { method: 'POST', device, body: { identifier, password: PASS } });
  if (!r.json || !r.json.token) throw new Error(`login failed for ${identifier}: ${r.status} ${r.text}`);
  return r.json;
}

async function expectStatus(label, path, opts, expected) {
  const r = await api(path, opts);
  record(label, r.status === expected, `got ${r.status}, expected ${expected}`);
  return r;
}

async function main() {
  const health = await api('/health').catch(() => null);
  if (!health || health.status !== 200) throw new Error('Backend is not running on :4000 -- start it with npm run dev first.');
  const ml = await fetch('http://127.0.0.1:5001/health').catch(() => null);
  if (!ml || !ml.ok) throw new Error('ML service is not running on :5001 -- start ml/service/app.py first.');

  console.log('Preparing dedicated test accounts (your real accounts are not touched)...');
  const cgAcct = await ensureTestAccount(ACCOUNTS.cg);
  const auAcct = await ensureTestAccount(ACCOUNTS.au);
  const adAcct = await ensureTestAccount(ACCOUNTS.ad);
  const cg2Acct = await ensureTestAccount(ACCOUNTS.cg2);
  await ageTestActivity([cgAcct.id, auAcct.id, adAcct.id, cg2Acct.id]);

  console.log('\n=== Authentication ===');
  const wrong = await api('/auth/login', { method: 'POST', body: { identifier: cgAcct.email, password: 'wrong-password' } });
  record('Wrong password is rejected (401)', wrong.status === 401, `got ${wrong.status}`);

  const deviceA = 'test-device-A';
  const cg = await login(ACCOUNTS.cg.username, deviceA); // by USERNAME
  record('Login with username works', Boolean(cg.token));
  record('Login response carries fullName', cg.fullName === ACCOUNTS.cg.name, `fullName=${cg.fullName}`);
  const au = await login(auAcct.email); // by EMAIL
  record('Login with email works', Boolean(au.token));
  const ad = await login(adAcct.email);

  const me = await api('/auth/me', { token: cg.token, device: deviceA });
  record('/auth/me returns fullName', me.json && me.json.fullName === ACCOUNTS.cg.name, JSON.stringify(me.json));

  console.log('\n=== RBAC: each role against every other role\'s routes ===');
  await expectStatus('Caregiver -> auditor flagged sessions (403)', '/auditor/flagged-sessions', { token: cg.token, device: deviceA }, 403);
  await expectStatus('Caregiver -> audit log (403)', '/auditor/audit-log', { token: cg.token, device: deviceA }, 403);
  await expectStatus('Caregiver -> admin registration requests (403)', '/admin/registration-requests', { token: cg.token, device: deviceA }, 403);
  await expectStatus('Caregiver -> admin locked users (403)', '/admin/users/locked', { token: cg.token, device: deviceA }, 403);
  await expectStatus('Caregiver -> encryption status (403)', '/admin/encryption/status', { token: cg.token, device: deviceA }, 403);
  await expectStatus('Auditor -> children (403)', '/children', { token: au.token }, 403);
  await expectStatus('Auditor -> create child (403)', '/children', { method: 'POST', token: au.token, body: { fullName: 'x', dateOfBirth: '2020-01-01' } }, 403);
  await expectStatus('Auditor -> admin registration requests (403)', '/admin/registration-requests', { token: au.token }, 403);
  await expectStatus('Auditor -> encryption re-encrypt (403)', '/admin/encryption/reencrypt', { method: 'POST', token: au.token }, 403);
  await expectStatus('Admin -> children (403)', '/children', { token: ad.token }, 403);
  await expectStatus('Admin -> auditor flagged sessions (403)', '/auditor/flagged-sessions', { token: ad.token }, 403);
  await expectStatus('Auditor -> own flagged sessions (200)', '/auditor/flagged-sessions?status=all', { token: au.token }, 200);
  await expectStatus('Auditor -> own audit log (200)', '/auditor/audit-log?limit=5', { token: au.token }, 200);
  await expectStatus('Admin -> own registration requests (200)', '/admin/registration-requests', { token: ad.token }, 200);
  await expectStatus('Admin -> own locked users (200)', '/admin/users/locked', { token: ad.token }, 200);
  await expectStatus('No token at all (401)', '/children', {}, 401);

  console.log('\n=== Caregiver: child profile, validation, consent ===');
  const tomorrow = new Date(Date.now() + 86400000).toISOString().slice(0, 10);
  const NOTICE = { privacyNoticeVersion: PRIVACY_NOTICE_VERSION };
  const noNotice = await api('/children', {
    method: 'POST', token: cg.token, device: deviceA, body: { fullName: 'No Notice Child', dateOfBirth: '2020-01-01' },
  });
  record('Child registration without accepting the privacy notice is refused (400, s.29)',
    noNotice.status === 400 && noNotice.json && noNotice.json.code === 'PRIVACY_NOTICE_REQUIRED', `status=${noNotice.status}`);
  const oldNotice = await api('/children', {
    method: 'POST', token: cg.token, device: deviceA, body: { fullName: 'Old Notice Child', dateOfBirth: '2020-01-01', privacyNoticeVersion: '2000-01' },
  });
  record('An outdated privacy notice version is refused (400)', oldNotice.status === 400, `status=${oldNotice.status}`);
  const regNoNotice = await api('/auth/register', {
    method: 'POST', body: { fullName: 'No Notice Person', email: testEmail('nonotice'), requestedRole: 'Caregiver' },
  });
  record('Account request without accepting the privacy notice is refused (400, s.29)',
    regNoNotice.status === 400 && regNoNotice.json && regNoNotice.json.code === 'PRIVACY_NOTICE_REQUIRED', `status=${regNoNotice.status}`);
  await expectStatus('Future date of birth is rejected (400)', '/children',
    { method: 'POST', token: cg.token, device: deviceA, body: { fullName: 'Future Child', dateOfBirth: tomorrow, ...NOTICE } }, 400);
  const created = await api('/children', {
    method: 'POST', token: cg.token, device: deviceA,
    body: { fullName: 'Test Child', dateOfBirth: '2020-06-15', familyBackground: 'Automated test record', ...NOTICE },
  });
  record('Caregiver creates child profile (201)', created.status === 201, `status=${created.status}`);
  record('Normal first action on a known device is NOT flagged', created.json && !created.json.riskNotice,
    created.json && created.json.riskNotice ? 'flagged' : 'not flagged');
  const childId = created.json && created.json.childProfileId;
  const list = await api('/children', { token: cg.token, device: deviceA });
  const mine = list.json && list.json.children.find((c) => c.childProfileId === childId);
  record('Child decrypts correctly in the list', mine && mine.fullName === 'Test Child' && mine.dateOfBirth === '2020-06-15');
  await expectStatus('Consent history is readable (200)', `/children/${childId}/consent`, { token: cg.token, device: deviceA }, 200);
  await expectStatus('Non-boolean records consent at registration is rejected (400)', '/children',
    { method: 'POST', token: cg.token, device: deviceA, body: { fullName: 'x', dateOfBirth: '2020-01-01', developmentalRecordsConsent: 'yes', ...NOTICE } }, 400);

  console.log('\n=== Consent enforcement on every records request ===');
  const recordBody = { milestone: 'Walks unaided', healthIndicator: 'Healthy', assessmentScore: 8 };
  const setRecordsConsent = (consentGiven) => api(`/children/${childId}/consent`, {
    method: 'POST', token: cg.token, device: deviceA, body: { scope: 'developmental_records', consentGiven },
  });
  const noConsent = await api(`/children/${childId}/records`, { token: cg.token, device: deviceA });
  record('Records blocked by default -- consent is opt-in (403 CONSENT_REQUIRED)',
    noConsent.status === 403 && noConsent.json && noConsent.json.code === 'CONSENT_REQUIRED', `status=${noConsent.status}`);
  await setRecordsConsent(true);
  await expectStatus('Records readable once consent is granted (200)', `/children/${childId}/records`, { token: cg.token, device: deviceA }, 200);
  await setRecordsConsent(false);
  const revokedView = await api(`/children/${childId}/records`, { token: cg.token, device: deviceA });
  record('Viewing records blocked after consent is revoked (403 CONSENT_REQUIRED)',
    revokedView.status === 403 && revokedView.json && revokedView.json.code === 'CONSENT_REQUIRED', `status=${revokedView.status}`);
  const revokedSubmit = await api(`/children/${childId}/records`, { method: 'POST', token: cg.token, device: deviceA, body: recordBody });
  record('Submitting a record blocked after consent is revoked (403 CONSENT_REQUIRED)',
    revokedSubmit.status === 403 && revokedSubmit.json && revokedSubmit.json.code === 'CONSENT_REQUIRED', `status=${revokedSubmit.status}`);
  const { rows: denials } = await db.query(
    "SELECT COUNT(*)::int AS n FROM audit_log WHERE user_id = $1 AND action = 'access_denied_no_consent' AND detail LIKE $2",
    [cgAcct.id, `child_profile_id=${childId},%`]
  );
  record('Every consent refusal is written to the audit log', denials[0].n === 3, `${denials[0].n} entries, expected 3`);
  await setRecordsConsent(true); // the risk-engine checks below view this child's records

  console.log('\n=== Correcting a child\'s details (KDPA s.26(d)) ===');
  const patch = (body, token = cg.token) => api(`/children/${childId}`, { method: 'PATCH', token, device: deviceA, body });
  record('Correction with no fields is rejected (400)', (await patch({})).status === 400);
  record('Correction to an empty name is rejected (400)', (await patch({ fullName: '   ' })).status === 400);
  record('Correction to a future date of birth is rejected (400)', (await patch({ dateOfBirth: tomorrow })).status === 400);
  record('Security Auditor cannot correct a child (403)', (await patch({ fullName: 'x' }, au.token)).status === 403);
  const corrected = await patch({ fullName: 'Test Child Corrected' });
  record('Caregiver corrects their child\'s name (200)',
    corrected.status === 200 && JSON.stringify(corrected.json.updatedFields) === '["fullName"]', `status=${corrected.status}`);
  const afterFix = await api('/children', { token: cg.token, device: deviceA });
  record('Corrected name is stored and decrypts',
    afterFix.json && afterFix.json.children.some((c) => c.childProfileId === childId && c.fullName === 'Test Child Corrected'));
  const { rows: fixLog } = await db.query(
    "SELECT detail FROM audit_log WHERE user_id = $1 AND action = 'correct_child_details' ORDER BY id DESC LIMIT 1", [cgAcct.id]);
  record('Audit log names the corrected field but never the child\'s name',
    fixLog[0] && fixLog[0].detail === `child_profile_id=${childId}, fields=fullName` && !fixLog[0].detail.includes('Test Child'),
    fixLog[0] && fixLog[0].detail);
  await patch({ fullName: 'Test Child' }); // later checks look for the original name

  console.log('\n=== Downloadable reports (Security Auditor) ===');
  await expectStatus('Caregiver cannot download reports (403)', '/auditor/reports/audit-log?format=csv', { token: cg.token, device: deviceA }, 403);
  await expectStatus('Admin cannot download reports (403)', '/auditor/reports/audit-log?format=csv', { token: ad.token }, 403);
  await expectStatus('Unknown report (404)', '/auditor/reports/everything', { token: au.token }, 404);
  await expectStatus('Unknown format (400)', '/auditor/reports/audit-log?format=xlsx', { token: au.token }, 400);
  await expectStatus('Malformed date (400)', '/auditor/reports/audit-log?from=30-10-2026', { token: au.token }, 400);
  await expectStatus('"from" after "to" (400)', '/auditor/reports/audit-log?from=2026-10-30&to=2026-10-01', { token: au.token }, 400);
  const { rows: exportsBefore } = await db.query(
    "SELECT COUNT(*)::int AS n FROM audit_log WHERE user_id = $1 AND action = 'export_report'", [auAcct.id]);
  const todayIso = new Date().toISOString().slice(0, 10);
  const auditCsv = await api(`/auditor/reports/audit-log?format=csv&from=${todayIso}`, { token: au.token });
  // (.text() strips the UTF-8 BOM while decoding; the BOM itself is covered by reportFormats.test.js)
  record('Audit log CSV downloads (200, header row)', auditCsv.status === 200 && auditCsv.text.startsWith('Time,User,Role,Action'),
    `status=${auditCsv.status}`);
  const pdf = await api(`/auditor/reports/flagged-sessions?format=pdf`, { token: au.token });
  record('Flagged sessions PDF downloads (200, real PDF)', pdf.status === 200 && pdf.text.startsWith('%PDF-'), `status=${pdf.status}`);
  const consentCsv = await api(`/auditor/reports/consent-activity?format=csv&from=${todayIso}`, { token: au.token });
  record('Consent report includes this run\'s refusals',
    consentCsv.status === 200 && consentCsv.text.includes(`,${childId},Access refused,Developmental records,view_developmental_records`),
    `status=${consentCsv.status}`);
  const { rows: exportsAfter } = await db.query(
    "SELECT COUNT(*)::int AS n FROM audit_log WHERE user_id = $1 AND action = 'export_report'", [auAcct.id]);
  record('Every download is written to the audit log', exportsAfter[0].n - exportsBefore[0].n === 3,
    `${exportsAfter[0].n - exportsBefore[0].n} new entries, expected 3`);

  console.log('\n=== Row-level security (enforced by PostgreSQL, not the app) ===');
  const asUser = (id, role, sql, params) => db.runAs({ userId: id, role }, () => db.query(sql, params));
  const count = async (id, role, sql, params) => (await asUser(id, role, sql, params)).rows[0].n;
  const { rows: rlsOn } = await db.query(
    "SELECT bool_and(relrowsecurity) AS on FROM pg_class WHERE relname IN ('child_profiles','child_identifiers','developmental_records','consent_records')");
  record('RLS is enabled on all four child-data tables', rlsOn[0].on === true,
    rlsOn[0].on ? '' : 'run backend/db/migration_rls.sql as postgres');
  if (rlsOn[0].on) {
    const { rows: others } = await db.runAsSystem(() => db.query(
      'SELECT id FROM child_profiles WHERE caregiver_id <> $1 ORDER BY id LIMIT 1', [cgAcct.id]));
    const otherChild = others[0] && others[0].id;
    const { rows: own } = await db.runAsSystem(() => db.query(
      'SELECT COUNT(*)::int AS n FROM child_profiles WHERE caregiver_id = $1', [cgAcct.id]));

    record('Caregiver query with NO filter returns only their own children',
      await count(cgAcct.id, 'Caregiver', 'SELECT COUNT(*)::int AS n FROM child_profiles') === own[0].n, `own=${own[0].n}`);
    record('Caregiver cannot read another family\'s child identity',
      await count(cgAcct.id, 'Caregiver', 'SELECT COUNT(*)::int AS n FROM child_identifiers WHERE child_profile_id = $1', [otherChild]) === 0,
      `other child #${otherChild}`);
    let blocked = false;
    try {
      await asUser(cgAcct.id, 'Caregiver',
        "INSERT INTO developmental_records (child_profile_id, milestone_enc, health_indicator_enc, assessment_score_enc, created_by) VALUES ($1, 'x', 'x', 'x', $2)",
        [otherChild, cgAcct.id]);
    } catch (err) {
      blocked = /row-level security/.test(err.message);
    }
    record('Caregiver cannot write a record against another family\'s child', blocked);
    const deleted = await asUser(cgAcct.id, 'Caregiver', 'DELETE FROM child_profiles WHERE id = $1', [childId]);
    record('Caregiver cannot delete even their own child profile (no delete policy)', deleted.rowCount === 0, `deleted ${deleted.rowCount}`);
    record('No identity at all sees zero child rows (deny by default)',
      (await db.query('SELECT COUNT(*)::int AS n FROM child_identifiers')).rows[0].n === 0);
    record('Security Auditor sees no child identities',
      await count(auAcct.id, 'SecurityAuditor', 'SELECT COUNT(*)::int AS n FROM child_identifiers') === 0);
    record('Security Auditor can read consent history (Consent report)',
      await count(auAcct.id, 'SecurityAuditor', 'SELECT COUNT(*)::int AS n FROM consent_records') > 0);
    record('SysAdmin sees no child identities',
      await count(adAcct.id, 'SysAdmin', 'SELECT COUNT(*)::int AS n FROM child_identifiers') === 0);
    record('Explicit System identity (key rotation) sees every child',
      (await db.runAsSystem(() => db.query('SELECT COUNT(*)::int AS n FROM child_identifiers'))).rows[0].n > 0);
  }

  console.log('\n=== Archive / restrict a child profile (KDPA s.40(3)) ===');
  const deviceC = 'test-device-C';
  const care2 = await login(ACCOUNTS.cg2.username, deviceC);
  const as2 = (path, opts = {}) => api(path, { token: care2.token, device: deviceC, ...opts });
  const kid = await as2('/children', {
    method: 'POST', body: { fullName: 'Archive Test Child', dateOfBirth: '2021-02-02', developmentalRecordsConsent: true, ...NOTICE },
  });
  const kidId = kid.json && kid.json.childProfileId;
  record('Second test caregiver registers a child (201)', kid.status === 201, `status=${kid.status}`);
  await expectStatus('Another caregiver cannot archive this child (403)', `/children/${kidId}/archive`,
    { method: 'POST', token: cg.token, device: deviceA, body: {} }, 403);
  const archivedRes = await as2(`/children/${kidId}/archive`, { method: 'POST', body: { reason: 'Left the programme' } });
  record('Owner archives the profile (200)', archivedRes.status === 200 && Boolean(archivedRes.json.archivedAt), `status=${archivedRes.status}`);
  const frozen = async (label, path, opts) => {
    const r = await as2(path, opts);
    record(label, r.status === 409 && r.json && r.json.code === 'PROFILE_ARCHIVED', `status=${r.status}`);
  };
  await frozen('Archived: records cannot be viewed (409)', `/children/${kidId}/records`);
  await frozen('Archived: records cannot be added (409)', `/children/${kidId}/records`, { method: 'POST', body: recordBody });
  await frozen('Archived: details cannot be corrected (409)', `/children/${kidId}`, { method: 'PATCH', body: { fullName: 'x' } });
  await frozen('Archived: consent cannot change (409)', `/children/${kidId}/consent`,
    { method: 'POST', body: { scope: 'developmental_records', consentGiven: false } });
  await expectStatus('Archiving twice is refused (409)', `/children/${kidId}/archive`, { method: 'POST', token: care2.token, device: deviceC, body: {} }, 409);
  let dbFrozen = false;
  try {
    await db.runAs({ userId: cg2Acct.id, role: 'Caregiver' }, () => db.query(
      "INSERT INTO developmental_records (child_profile_id, milestone_enc, health_indicator_enc, assessment_score_enc, created_by) VALUES ($1, 'x', 'x', 'x', $2)",
      [kidId, cg2Acct.id]));
  } catch (err) {
    dbFrozen = /row-level security/.test(err.message);
  }
  record('Database itself refuses new records for an archived child (RLS)', dbFrozen);
  const listed = await as2('/children');
  record('Archived child is still listed, marked archived (nothing deleted)',
    listed.json && listed.json.children.some((c) => c.childProfileId === kidId && c.archivedAt && c.fullName === 'Archive Test Child'));
  const { rows: archLog } = await db.query(
    "SELECT detail FROM audit_log WHERE user_id = $1 AND action = 'archive_child_profile' ORDER BY id DESC LIMIT 1", [cg2Acct.id]);
  record('Audit log records the archive but not the free-text reason',
    archLog[0] && archLog[0].detail === `child_profile_id=${kidId}, reason given`, archLog[0] && archLog[0].detail);
  const restored = await as2(`/children/${kidId}/restore`, { method: 'POST' });
  record('Owner restores the profile (200)', restored.status === 200, `status=${restored.status}`);
  await expectStatus('Restored: records viewable again (200)', `/children/${kidId}/records`, { token: care2.token, device: deviceC }, 200);

  console.log('\n=== Retention: anonymising archived profiles (KDPA s.39) ===');
  await expectStatus('Caregiver cannot see retention status (403)', '/admin/retention/status', { token: cg.token, device: deviceA }, 403);
  await expectStatus('Auditor cannot apply retention (403)', '/admin/retention/apply', { method: 'POST', token: au.token }, 403);
  await as2(`/children/${kidId}/archive`, { method: 'POST', body: {} });
  // Simulate the retention period having passed -- for THIS test child only.
  await db.runAsSystem(() => db.query(
    "UPDATE child_profiles SET archived_at = now() - interval '400 days' WHERE id = $1", [kidId]));
  const retStatus = await api('/admin/retention/status', { token: ad.token });
  record('SysAdmin sees retention status (200)', retStatus.status === 200 && retStatus.json.due >= 1, retStatus.json && `due=${retStatus.json.due}`);
  // Never anonymise real data from a test run: only proceed if every
  // profile due right now belongs to a test account.
  const { rows: dueOwners } = await db.runAsSystem(() => db.query(
    `SELECT COUNT(*) FILTER (WHERE caregiver_id <> ALL($1))::int AS other FROM child_profiles
     WHERE archived_at IS NOT NULL AND identity_anonymised_at IS NULL
       AND archived_at < now() - make_interval(days => $2)`,
    [[cgAcct.id, cg2Acct.id], Number(process.env.RETENTION_DAYS) || 365]));
  if (dueOwners[0].other > 0) {
    record('Retention apply (SKIPPED: real profiles are due -- not anonymising them from a test run)', true);
  } else {
    const applied = await api('/admin/retention/apply', { method: 'POST', token: ad.token });
    record('SysAdmin applies retention (200) and this child is anonymised',
      applied.status === 200 && applied.json.childProfileIds.includes(kidId), applied.json && `anonymised=${applied.json.anonymised}`);
    const afterRet = await as2('/children');
    const anon = afterRet.json && afterRet.json.children.find((c) => c.childProfileId === kidId);
    record('Identity replaced with a placeholder; profile kept',
      anon && anon.fullName === 'Anonymised child' && anon.familyBackground === null && Boolean(anon.anonymisedAt), anon && anon.fullName);
    const { rows: stillThere } = await db.runAsSystem(() => db.query(
      'SELECT (SELECT COUNT(*) FROM consent_records WHERE child_profile_id = $1)::int AS consents', [kidId]));
    record('Consent history kept for the audit trail', stillThere[0].consents > 0, `${stillThere[0].consents} consent rows`);
    await expectStatus('Anonymised profile cannot be restored (409)', `/children/${kidId}/restore`,
      { method: 'POST', token: care2.token, device: deviceC }, 409);
  }

  console.log('\n=== ML risk engine: same caregiver signs in from a NEW device ===');
  const deviceB = `test-device-B-${crypto.randomBytes(3).toString('hex')}`;
  const cg2 = await login(cgAcct.email, deviceB);
  const view = await api(`/children/${childId}/records`, { token: cg2.token, device: deviceB });
  record('Viewing records still succeeds (200)', view.status === 200, `status=${view.status}`);
  const flagged = Boolean(view.json && view.json.riskNotice);
  record('Action from an unrecognised device IS flagged', flagged, flagged ? 'riskNotice returned' : 'not flagged');

  let riskScoreId = null;
  if (flagged) {
    const after = await api('/children', { token: cg2.token, device: deviceB });
    record('Flagged session is revoked (next call 401)', after.status === 401, `status=${after.status}`);
    record('401 explains it was a risk sign-out', after.json && after.json.code === 'SESSION_REVOKED_RISK', after.json && after.json.code);
    const firstSession = await api('/children', { token: cg.token, device: deviceA });
    record('The other (device A) session is unaffected', firstSession.status === 200, `status=${firstSession.status}`);

    const { rows } = await db.query(
      `SELECT rs.id, rs.combined_score, rs.role_threshold FROM risk_scores rs
       JOIN access_requests ar ON ar.id = rs.access_request_id
       WHERE ar.user_id = $1 AND rs.is_flagged ORDER BY rs.created_at DESC LIMIT 1`,
      [cgAcct.id]
    );
    riskScoreId = rows[0].id;
    console.log(`     risk score ${Number(rows[0].combined_score).toFixed(3)} vs threshold ${rows[0].role_threshold}`);

    console.log('\n=== Security Auditor reviews it ===');
    const queue = await api('/auditor/flagged-sessions?status=pending', { token: au.token });
    record('Flagged session appears in the auditor queue', queue.json && queue.json.flaggedSessions.some((s) => s.risk_score_id === riskScoreId));
    await expectStatus('Auditor sets status=reviewing', `/auditor/flagged-sessions/${riskScoreId}/review`,
      { method: 'POST', token: au.token, body: { status: 'reviewing' } }, 200);
    await expectStatus('Auditor rejects an invalid status (400)', `/auditor/flagged-sessions/${riskScoreId}/review`,
      { method: 'POST', token: au.token, body: { status: 'bogus' } }, 400);
    await expectStatus('Auditor sets status=confirmed', `/auditor/flagged-sessions/${riskScoreId}/review`,
      { method: 'POST', token: au.token, body: { status: 'confirmed' } }, 200);

    console.log('\n=== Owner\'s "This was me" link ===');
    const confirmToken = signRiskResponseToken(riskScoreId, 'confirm');
    const c1 = await api(`/risk-response/${riskScoreId}/confirm?token=${confirmToken}`);
    record('Confirm link accepted', c1.status === 200 && c1.text.includes('Thanks for confirming'), `status=${c1.status}`);
    const c2 = await api(`/risk-response/${riskScoreId}/confirm?token=${confirmToken}`);
    record('Second click is a harmless no-op', c2.text.includes('already responded'));
    const d1 = await api(`/risk-response/${riskScoreId}/deny?token=${signRiskResponseToken(riskScoreId, 'deny')}`);
    record('Deny after confirm is also a no-op (no lock)', d1.text.includes('already responded'));
    const bad = await api(`/risk-response/${riskScoreId}/confirm?token=forged`);
    record('Forged link token is refused', bad.status >= 400, `status=${bad.status}`);

    console.log('\n=== Breach decision on a suspected breach (KDPA s.43) ===');
    const decide = (body, token = au.token) => api(`/auditor/flagged-sessions/${riskScoreId}/breach-decision`, { method: 'POST', token, body });
    const valid = { decision: 'no_real_risk', reason: 'Automated test: owner confirmed, known test device' };
    record('Not a breach candidate while confirmed and owner said "this was me" (409)', (await decide(valid)).status === 409);
    await api(`/auditor/flagged-sessions/${riskScoreId}/review`, { method: 'POST', token: au.token, body: { status: 'escalated' } });
    record('Unknown decision is rejected (400)', (await decide({ ...valid, decision: 'ignored' })).status === 400);
    record('A decision without reasoning is rejected (400)', (await decide({ ...valid, reason: 'ok' })).status === 400);
    record('Caregiver cannot record a breach decision (403)', (await decide(valid, cg.token)).status === 403);
    const decided = await decide(valid);
    record('Auditor records the decision on an escalated session (200, within 72 h)',
      decided.status === 200 && decided.json.withinWindow === true, decided.json && `${decided.json.hoursAfterFlag} h after flag`);
    record('The decision cannot be changed afterwards (409)', (await decide({ ...valid, decision: 'notified_commissioner' })).status === 409);
    const { rows: brLog } = await db.query(
      "SELECT detail FROM audit_log WHERE user_id = $1 AND action = 'breach_decision_recorded' ORDER BY id DESC LIMIT 1", [auAcct.id]);
    record('Breach decision is in the audit log with its timing',
      brLog[0] && brLog[0].detail.startsWith(`risk_score_id=${riskScoreId}, decision=no_real_risk`) && brLog[0].detail.includes('within_72h=true'),
      brLog[0] && brLog[0].detail);
  }

  console.log('\n=== SysAdmin: encryption keys + account actions ===');
  const enc = await api('/admin/encryption/status', { token: ad.token });
  record('Encryption status loads (200)', enc.status === 200, enc.json ? `active key #${enc.json.activeKeyId}` : '');
  record('Encryption status never exposes key material', enc.json && !JSON.stringify(enc.json).match(/[A-Za-z0-9+/]{43}=/));
  const re = await api('/admin/encryption/reencrypt', { method: 'POST', token: ad.token });
  record('Re-encrypt runs (200) and leaves nothing behind', re.status === 200 && re.json.status.needsReencryption === 0,
    re.json ? `updated ${re.json.updatedValues} value(s)` : `status=${re.status}`);
  const relist = await api('/children', { token: cg.token, device: deviceA });
  const still = relist.json && relist.json.children.find((c) => c.childProfileId === childId);
  record('Child data still decrypts after re-encryption', still && still.fullName === 'Test Child');
  await expectStatus('Caregiver cannot unlock accounts (403)', `/admin/users/${cgAcct.id}/unlock`, { method: 'POST', token: cg.token, device: deviceA }, 403);
  await expectStatus('Unlocking a not-locked account (409)', `/admin/users/${cgAcct.id}/unlock`, { method: 'POST', token: ad.token }, 409);
  await expectStatus('Unlocking a nonexistent user (404)', '/admin/users/999999/unlock', { method: 'POST', token: ad.token }, 404);
  await expectStatus('Approving a nonexistent request (404)', '/admin/registration-requests/999999/approve', { method: 'POST', token: ad.token }, 404);

  console.log('\n=== SUMMARY ===');
  const failed = results.filter((r) => !r.ok);
  console.log(`${results.length - failed.length}/${results.length} passed.`);
  failed.forEach((f) => console.log(`  FAILED: ${f.name} :: ${f.detail || ''}`));
  return failed.length;
}

main()
  .then(async (failures) => {
    await lockTestAccounts();
    await db.pool.end();
    process.exit(failures ? 1 : 0);
  })
  .catch(async (err) => {
    console.error(err);
    try { await lockTestAccounts(); await db.pool.end(); } catch { /* ignore */ }
    process.exit(1);
  });
