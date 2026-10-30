// Response-time test for the proposal's non-functional requirement:
// "a response time of less than one second for access control decisions".
//
// Run from backend/:   npm run test:perf   (backend on :4000, ML on :5001)
//
// Signs in as the dedicated test caregiver (same accounts as test:api) and
// times real HTTPS requests through the running system, one scenario at a
// time, from the simplest access-control decision to the full pipeline with
// ML scoring. Reports min / median / 95th percentile / max per scenario and
// checks the 95th percentile against 1000 ms. Results are also saved as
// JSON in test/results/ for the test report.
//
// Only a handful of requests are ML-scored (scenario E): firing 50 scored
// data reads in a minute is exactly the burst the risk model exists to
// catch, and would (correctly) end the test session.
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });

// Same self-signed-certificate handling as rbac_and_edgecase_test.js.
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
const { PRIVACY_NOTICE_VERSION } = require('../src/services/privacyNotice');

const BASE = `${process.env.TLS_CERT_FILE ? 'https' : 'http'}://localhost:4000`;
const ML = process.env.ML_SERVICE_URL || 'http://127.0.0.1:5001';
const LIMIT_MS = 1000;
const RUNS = 50;
const DEVICE = 'test-device-A';
const PASS = `T3st-${crypto.randomBytes(9).toString('base64url')}`;
const inbox = (process.env.SMTP_USER || 'test@example.com').split('@');
const EMAIL = `${inbox[0]}+childguard-test-caregiver@${inbox[1]}`;

async function api(p, { method = 'GET', token, body } = {}) {
  const headers = { 'Content-Type': 'application/json', 'X-Device-Name': DEVICE };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(`${BASE}${p}`, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* not json */ }
  return { status: res.status, json };
}

// Times `fn` `runs` times in a row; checks every response is the expected one.
async function measure(fn, runs, expectStatus) {
  const times = [];
  for (let i = 0; i < runs; i++) {
    const start = performance.now();
    const r = await fn();
    times.push(performance.now() - start);
    if (r.status !== expectStatus) throw new Error(`expected ${expectStatus}, got ${r.status} ${JSON.stringify(r.json)}`);
  }
  return times;
}

function stats(times) {
  const s = [...times].sort((a, b) => a - b);
  const pick = (q) => s[Math.min(s.length - 1, Math.ceil(q * s.length) - 1)];
  return { n: s.length, min: s[0], median: pick(0.5), p95: pick(0.95), max: s[s.length - 1] };
}

// node --watch can restart the backend when this script loads backend files
// (see README), so wait until it answers steadily before timing anything.
async function waitForBackend() {
  let ok = 0;
  for (let i = 0; i < 40 && ok < 3; i++) {
    try {
      ok = (await fetch(`${BASE}/health`)).ok ? ok + 1 : 0;
    } catch {
      ok = 0;
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  if (ok < 3) throw new Error('Backend is not answering on :4000 -- start it first.');
}

async function main() {
  await waitForBackend();
  if (!(await fetch(`${ML}/health`).catch(() => null))?.ok) throw new Error('ML service is not running on :5001.');

  // Same dedicated test caregiver as test:api; earlier activity aged two
  // days so this run starts like a fresh working day.
  const { rows: users } = await db.query('SELECT id FROM users WHERE email = $1', [EMAIL]);
  if (!users[0]) throw new Error('Test caregiver missing -- run `npm run test:api` once first.');
  const cgId = users[0].id;
  await db.query(
    `UPDATE users SET password_hash = $1, is_locked = FALSE, locked_reason = NULL,
            must_change_password = FALSE, mfa_required = FALSE WHERE id = $2`,
    [await bcrypt.hash(PASS, 10), cgId]
  );
  await db.query("UPDATE access_requests SET requested_at = requested_at - interval '2 days' WHERE user_id = $1", [cgId]);

  try {
    const login = await api('/auth/login', { method: 'POST', body: { identifier: EMAIL, password: PASS } });
    const token = login.json && login.json.token;
    if (!token) throw new Error(`login failed: ${login.status}`);

    // Fixtures: one own child WITH records consent, one WITHOUT, and some
    // other family's child.
    const make = async (consent) => (await api('/children', {
      method: 'POST', token,
      body: { fullName: 'Perf Test Child', dateOfBirth: '2021-01-01', developmentalRecordsConsent: consent, privacyNoticeVersion: PRIVACY_NOTICE_VERSION },
    })).json.childProfileId;
    const withConsent = await make(true);
    const withoutConsent = await make(false);
    const { rows: other } = await db.runAsSystem(() => db.query(
      'SELECT id FROM child_profiles WHERE caregiver_id <> $1 ORDER BY id LIMIT 1', [cgId]));

    const features = {
      files_accessed_per_session: 2, events_prev_day: 4, events_prev_hour: 4,
      unique_pcs_used_that_day: 1, session_duration_minutes: 5, is_after_hours: 0, is_own_pc: 1,
    };
    // E runs FIRST: D and G below each make 50 list requests in under a
    // minute, which the risk model would rightly read as a burst and use to
    // end the session at E's next scored request.
    const scenarios = [
      ['E. Full pipeline incl. ML scoring (own child\'s records)', () => api(`/children/${withConsent}/records`, { token }), 3, 200],
      ['A. Role check refuses (caregiver -> audit log)', () => api('/auditor/audit-log', { token }), RUNS, 403],
      ['B. Ownership check refuses (another family\'s child)', () => api(`/children/${other[0].id}/records`, { token }), RUNS, 403],
      ['C. Consent check refuses (no consent, logged)', () => api(`/children/${withoutConsent}/records`, { token }), RUNS, 403],
      ['D. Allowed: own children list (RLS + decrypt + log)', () => api('/children', { token }), RUNS, 200],
      ['F. ML risk scoring alone (Flask model)', async () => {
        const r = await fetch(`${ML}/score`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ role: 'Caregiver', features }) });
        return { status: r.status, json: await r.json() };
      }, RUNS, 200],
    ];

    const results = [];
    for (const [name, fn, runs, expect] of scenarios) {
      process.stdout.write(`Timing ${name} ...`);
      results.push({ name, ...stats(await measure(fn, runs, expect)) });
      process.stdout.write(' done\n');
    }

    // Load: 10 caregivers' worth of list requests at the same time, 5 rounds.
    process.stdout.write('Timing G. Under load: 10 simultaneous list requests ...');
    const loadTimes = [];
    for (let round = 0; round < 5; round++) {
      const batch = await Promise.all(Array.from({ length: 10 }, async () => {
        const start = performance.now();
        const r = await api('/children', { token });
        if (r.status !== 200) throw new Error(`expected 200, got ${r.status}`);
        return performance.now() - start;
      }));
      loadTimes.push(...batch);
    }
    results.push({ name: 'G. Under load: 10 simultaneous list requests', ...stats(loadTimes) });
    process.stdout.write(' done\n');

    results.sort((a, b) => a.name.localeCompare(b.name)); // print A..G
    const ms = (v) => `${v.toFixed(0)} ms`.padStart(8);
    console.log(`\n${'Scenario'.padEnd(58)}${'runs'.padStart(5)}${'min'.padStart(8)}${'median'.padStart(9)}${'95th %'.padStart(9)}${'max'.padStart(8)}  result`);
    console.log('-'.repeat(108));
    for (const r of results) {
      const ok = r.p95 < LIMIT_MS;
      r.pass = ok;
      console.log(`${r.name.padEnd(58)}${String(r.n).padStart(5)}${ms(r.min)}${ms(r.median).padStart(9)}${ms(r.p95).padStart(9)}${ms(r.max)}  ${ok ? 'PASS' : 'FAIL'}`);
    }
    const allPass = results.every((r) => r.pass);
    console.log(`\nRequirement: access-control decisions answered in under ${LIMIT_MS} ms (95th percentile).`);
    console.log(allPass ? 'RESULT: PASS -- every scenario is under 1 second.' : 'RESULT: FAIL -- see the scenarios marked FAIL.');

    const outDir = path.join(__dirname, 'results');
    fs.mkdirSync(outDir, { recursive: true });
    const outFile = path.join(outDir, `performance_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.json`);
    fs.writeFileSync(outFile, JSON.stringify({ ranAt: new Date().toISOString(), limitMs: LIMIT_MS, results }, null, 2));
    console.log(`Saved: ${path.relative(path.join(__dirname, '..'), outFile)}`);
    return allPass ? 0 : 1;
  } finally {
    await db.query(
      "UPDATE users SET is_locked = TRUE, locked_reason = 'automated test account (locked between runs)' WHERE id = $1", [cgId]);
  }
}

main()
  .then(async (code) => { await db.pool.end(); process.exit(code); })
  .catch(async (err) => {
    console.error('\nTest could not complete:', err.message, err.cause ? `(${err.cause.code || err.cause.message})` : '');
    try { await db.pool.end(); } catch { /* ignore */ }
    process.exit(1);
  });
