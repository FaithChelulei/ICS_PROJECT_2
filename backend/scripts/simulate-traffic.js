// Live traffic simulator and threshold calibration
// ================================================
// The anomaly models were trained on CERT r4.2 (office workers, 2010). This
// script answers the question that leaves open: how do the SAME models
// behave on traffic shaped like this app's own users, and which threshold
// keeps false sign-outs inside an alert budget while still catching misuse?
// (Recommended in the mentorship review, section 06, step 5.)
//
// What it does
//   1. Creates dedicated simulated accounts (never real users):
//      30 caregivers, 5 security auditors, 3 system administrators, plus
//      7 scripted insiders who behave normally until their attack day.
//   2. Replays two weeks of activity day by day with a simulated clock.
//      Each action goes through the live system's own code path:
//      access_requests row -> computeFeatures() -> Flask /score.
//      Nothing is emailed, no session is revoked and no risk_scores rows
//      are written, so the run has no side effects on real users.
//   3. Week 1 (days 1-7) is the CALIBRATION week: from the normal users'
//      scores it picks, per role, the lowest threshold that keeps false
//      flags within the alert budget (default 1% of scored actions).
//   4. Week 2 (days 8-14) is the EVALUATION week: it reports false flags
//      of normal users and whether (and how fast) each insider is caught,
//      both at the current deployment thresholds and at the calibrated ones.
//
// Simplification: every action is scored and recorded as if no earlier
// flag had ended the session, so one run can be evaluated at any threshold.
// For an insider, "detected" means the first attack action whose score
// reaches the threshold. The report-download limit (10/hour) and the
// consent check are not simulated: this measures the model alone.
//
// Run from backend/ with the ML service on :5001 (the backend API is not
// needed):   npm run sim:traffic
// Options:   --seed 42  --budget 0.01  --keep (keep the simulated rows)
// Output:    test/results/simulation_<timestamp>.json  (+ _actions.csv)
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });

const fs = require('fs');
const path = require('path');
const db = require('../src/config/db');
const { computeFeatures } = require('../src/services/featureComputation');
const { logAccessRequest } = require('../src/services/riskEngine');
const { scoreSession } = require('../src/utils/mlClient');

// ---------------------------------------------------------------- options
const arg = (name, dflt) => {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 ? process.argv[i + 1] : dflt;
};
const SEED = Number(arg('seed', 42));
const BUDGET = Number(arg('budget', 0.01));
const KEEP = process.argv.includes('--keep');
const DAYS = 14;
const CALIBRATION_DAYS = 7;
// A fixed Monday in the past, so simulated days never overlap real activity.
const START = new Date(2026, 8, 7);
const CURRENT = { Caregiver: 0.40, SecurityAuditor: 0.65, SysAdmin: 0.60 };

// ------------------------------------------------- seeded random numbers
let rngState = SEED >>> 0;
function rand() { // mulberry32
  rngState = (rngState + 0x6d2b79f5) >>> 0;
  let t = rngState;
  t = Math.imul(t ^ (t >>> 15), t | 1);
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
}
const between = (a, b) => a + rand() * (b - a);
const intBetween = (a, b) => Math.floor(between(a, b + 1));
const chance = (p) => rand() < p;
function pick(weighted) { // [[value, weight], ...]
  const total = weighted.reduce((s, [, w]) => s + w, 0);
  let r = rand() * total;
  for (const [v, w] of weighted) { if ((r -= w) <= 0) return v; }
  return weighted[weighted.length - 1][0];
}
const at = (day, hours) => {
  const d = new Date(START);
  d.setDate(d.getDate() + day - 1);
  d.setMinutes(Math.round(hours * 60));
  return d;
};
const isWeekday = (day) => { const w = at(day, 12).getDay(); return w >= 1 && w <= 5; };
const addMin = (d, m) => new Date(d.getTime() + m * 60000);

// ------------------------------------------------------ normal behaviour
// Each generator returns a list of sessions: { start, device, actions },
// where an action is { type, at, attack }.
const CAREGIVER_ACTIONS = [['view_own_child_records', 70], ['submit_developmental_record', 25], ['correct_child_details', 5]];
const CAREGIVER_COUNT = [[1, 25], [2, 25], [3, 20], [4, 12], [5, 8], [6, 5], [8, 3], [10, 2]];
const AUDITOR_ACTIONS = [['review_flagged_session', 50], ['view_audit_log', 35], ['export_report', 15]];
const ADMIN_ACTIONS = [['approve_registration', 50], ['unlock_account', 30], ['reject_registration', 15], ['reencrypt_data', 5]];

function actionsFrom(start, count, types, gapMin, gapMax) {
  const out = [];
  let t = addMin(start, between(0.5, 2)); // the dashboard list loads first
  for (let i = 0; i < count; i += 1) {
    out.push({ type: pick(types), at: t, attack: false });
    t = addMin(t, between(gapMin, gapMax));
  }
  return out;
}

function caregiverProfile(n) {
  const late = n % 10 === 0; // 3 of 30 caregivers use the app in the late evening
  return {
    activeProb: between(0.55, 0.85),
    slots: late ? [between(19.5, 21)] : [pick([[between(7, 9), 1], [between(12, 14), 1], [between(17, 19.5), 1]])],
    secondSlotGap: between(3, 6),
    devices: chance(0.2) ? ['laptop', 'phone'] : ['laptop'],
    late,
  };
}

function caregiverDay(p, day, firstDay) {
  if (!firstDay && !chance(p.activeProb)) return [];
  const sessions = [];
  const n = pick([[1, 75], [2, 25]]);
  for (let s = 0; s < n; s += 1) {
    const hour = Math.min(p.slots[0] + s * p.secondSlotGap + between(-0.6, 0.6), p.late ? 21.7 : 19.8);
    const start = at(day, Math.max(6.25, hour));
    const device = p.devices.length > 1 && chance(0.3) ? p.devices[1] : p.devices[0];
    const actions = [];
    if (firstDay && s === 0) {
      for (let c = 0; c < intBetween(1, 3); c += 1) actions.push({ type: 'create_child_profile', at: addMin(start, 1 + c * 3), attack: false });
    }
    const more = actionsFrom(actions.length ? addMin(start, actions.length * 3 + 1) : start, pick(CAREGIVER_COUNT), CAREGIVER_ACTIONS, 1, 6);
    sessions.push({ start, device, actions: actions.concat(more) });
  }
  return sessions;
}

function auditorDay(day) {
  if (!isWeekday(day) || !chance(0.9)) return [];
  const sessions = [];
  const n = pick([[1, 60], [2, 40]]);
  let hour = between(8, 11);
  for (let s = 0; s < n; s += 1) {
    const start = at(day, hour);
    sessions.push({ start, device: 'office-pc', actions: actionsFrom(start, intBetween(2, 6), AUDITOR_ACTIONS, 1, 5) });
    hour += between(2.5, 5);
  }
  return sessions;
}

function adminDay(day) {
  if (!isWeekday(day) || !chance(0.9)) return [];
  const sessions = [];
  const n = intBetween(1, 3);
  let hour = between(8, 10);
  for (let s = 0; s < n; s += 1) {
    const start = at(day, hour);
    sessions.push({ start, device: 'admin-pc', actions: actionsFrom(start, intBetween(1, 3), ADMIN_ACTIONS, 1, 4) });
    hour += between(1.5, 3);
  }
  return sessions;
}

function normalSchedule(role, profile) {
  const out = [];
  for (let day = 1; day <= DAYS; day += 1) {
    if (role === 'Caregiver') out.push(...caregiverDay(profile, day, day === 1).map((s) => ({ ...s, day })));
    if (role === 'SecurityAuditor') out.push(...auditorDay(day).map((s) => ({ ...s, day })));
    if (role === 'SysAdmin') out.push(...adminDay(day).map((s) => ({ ...s, day })));
  }
  return out;
}

// ------------------------------------------------------ scripted insiders
const attackActions = (start, count, types, gapMin, gapMax) =>
  actionsFrom(start, count, types, gapMin, gapMax).map((a) => ({ ...a, attack: true }));

const INSIDERS = [
  {
    tag: 'cg-bulk', role: 'Caregiver', day: 10,
    scenario: 'Caregiver bulk-reads records in usual hours (CERT scenario 2, data theft)',
    attack(sched, p) {
      const start = at(10, p.late ? 19 : 10);
      return sched.filter((s) => s.day !== 10).concat([{ day: 10, start, device: p.devices[0],
        actions: attackActions(start, 40, [['view_own_child_records', 1]], 0.5, 1) }]);
    },
  },
  {
    tag: 'cg-night', role: 'Caregiver', day: 11,
    scenario: 'Caregiver reads records at 23:10 (CERT scenario 1, after hours)',
    attack(sched, p) {
      const start = at(11, 23 + 10 / 60);
      return sched.concat([{ day: 11, start, device: p.devices[0],
        actions: attackActions(start, 6, [['view_own_child_records', 1]], 2, 4) }]);
    },
  },
  {
    tag: 'cg-stolen', role: 'Caregiver', day: 12,
    scenario: 'Stolen caregiver password used from an unrecognised device, after the owner worked that morning',
    attack(sched, p) {
      const own = at(12, 8);
      const thief = at(12, 15);
      return sched.filter((s) => s.day !== 12).concat([
        { day: 12, start: own, device: p.devices[0], actions: actionsFrom(own, 3, CAREGIVER_ACTIONS, 2, 5) },
        { day: 12, start: thief, device: 'unrecognised-device', actions: attackActions(thief, 10, [['view_own_child_records', 1]], 1, 2) },
      ]);
    },
  },
  {
    tag: 'cg-quiet', role: 'Caregiver', day: 8,
    scenario: 'Quiet insider: reads about twice the usual amount, in usual hours, all of week 2',
    attack(sched) {
      return sched.map((s) => (s.day < 8 ? s : { ...s,
        actions: attackActions(s.start, Math.max(2, s.actions.length * 2), [['view_own_child_records', 1]], 1, 4) }));
    },
  },
  {
    tag: 'aud-scrape', role: 'SecurityAuditor', day: 9,
    scenario: 'Auditor scrapes the audit log and reports: 25 actions in about 40 minutes',
    attack(sched) {
      const start = at(9, 10);
      return sched.filter((s) => s.day !== 9).concat([{ day: 9, start, device: 'office-pc',
        actions: attackActions(start, 25, [['export_report', 1], ['view_audit_log', 1]], 1, 2) }]);
    },
  },
  {
    tag: 'adm-burst', role: 'SysAdmin', day: 10,
    scenario: 'Administrator fires 15 privileged actions in about 20 minutes (CERT scenario 3)',
    attack(sched) {
      const start = at(10, 14);
      return sched.filter((s) => s.day !== 10).concat([{ day: 10, start, device: 'admin-pc',
        actions: attackActions(start, 15, [['unlock_account', 2], ['reencrypt_data', 1], ['approve_registration', 2]], 1, 1.5) }]);
    },
  },
  {
    tag: 'adm-night', role: 'SysAdmin', day: 13,
    scenario: 'Administrator works at 22:00 on a Saturday',
    attack(sched) {
      const start = at(13, 22);
      return sched.concat([{ day: 13, start, device: 'admin-pc',
        actions: attackActions(start, 3, [['unlock_account', 1], ['reencrypt_data', 1]], 2, 4) }]);
    },
  },
];

// ------------------------------------------------------- accounts
const SIM_DOMAIN = 'childguard-sim.test';
const simEmail = (tag) => `sim-${tag}@${SIM_DOMAIN}`;

async function simUser(tag, role) {
  const { rows: roleRows } = await db.query('SELECT id FROM roles WHERE name = $1', [role]);
  const email = simEmail(tag);
  let { rows } = await db.query('SELECT id FROM users WHERE email = $1', [email]);
  if (!rows[0]) {
    // No usable password: these accounts are never signed in to.
    ({ rows } = await db.query(
      `INSERT INTO users (email, full_name, username, password_hash, role_id, mfa_required, must_change_password, is_locked)
       VALUES ($1, $2, $3, '!', $4, FALSE, FALSE, TRUE) RETURNING id`,
      [email, `Simulated ${role} ${tag}`, `sim.${tag}`, roleRows[0].id]));
  }
  return rows[0].id;
}

async function clearSimActivity() {
  const ids = `(SELECT id FROM users WHERE email LIKE '%@${SIM_DOMAIN}')`;
  await db.query(`DELETE FROM access_requests WHERE user_id IN ${ids}`);
  await db.query(`DELETE FROM sessions WHERE user_id IN ${ids}`);
}

// ------------------------------------------------------- replay
async function replayUser(u, out) {
  const sessions = u.schedule.slice().sort((a, b) => a.start - b.start);
  for (const s of sessions) {
    const { rows } = await db.query('INSERT INTO sessions (user_id, issued_at) VALUES ($1, $2) RETURNING id', [u.id, s.start]);
    const sessionId = rows[0].id;
    const pcName = `${u.tag}-${s.device}`;
    const base = { userId: u.id, pcName, ipAddress: '127.0.0.1', sessionId };
    await logAccessRequest({ ...base, actionType: 'login', now: s.start });
    await logAccessRequest({ ...base, actionType: u.role === 'Caregiver' ? 'list_own_children' : 'view_overview', now: addMin(s.start, 0.3) });
    for (const a of s.actions) {
      await logAccessRequest({ ...base, actionType: a.type, now: a.at });
      const features = await computeFeatures({ userId: u.id, sessionId, pcName, now: a.at, role: u.role });
      const r = await scoreSession(u.role, features);
      if (!r) throw new Error('ML service did not answer -- start ml/service/app.py first');
      out.push({
        user: u.tag, role: u.role, kind: u.kind, day: s.day, sessionStart: s.start.toISOString(), phase: s.day <= CALIBRATION_DAYS ? 'calibration' : 'evaluation',
        at: a.at.toISOString(), localHour: a.at.getHours() + a.at.getMinutes() / 60, action: a.type, attack: a.attack,
        ...features, iso: r.iso_score, ae: r.ae_score, risk: r.risk_score,
      });
    }
  }
}

async function inPool(items, size, fn) {
  let i = 0;
  const workers = Array.from({ length: size }, async () => {
    while (i < items.length) { const item = items[i]; i += 1; await fn(item); }
  });
  await Promise.all(workers);
}

// ------------------------------------------------------- analysis
const ROLES = ['Caregiver', 'SecurityAuditor', 'SysAdmin'];
const round = (x, d = 4) => Math.round(x * 10 ** d) / 10 ** d;
function quantile(sorted, q) {
  if (!sorted.length) return null;
  const pos = (sorted.length - 1) * q;
  const lo = Math.floor(pos);
  const hi = Math.ceil(pos);
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (pos - lo);
}

// Lowest threshold (to 2 decimals) that flags no more than BUDGET of the
// normal calibration-week actions of this role.
// Returns null when no threshold below 1.0 meets the budget, which means
// some normal behaviour already scores at the top of the scale.
function calibrate(scores) {
  for (let t = 0.3; t < 1; t = round(t + 0.01, 2)) {
    if (scores.filter((s) => s >= t).length / scores.length <= BUDGET) return t;
  }
  return null;
}

// Why a normal action was flagged, in the order the features usually
// explain it: night-time use, a device not seen before or a second device
// that day, otherwise the volume of activity.
function cause(r) {
  if (r.is_after_hours === 1) return 'after_hours';
  if (r.is_own_pc === 0 || r.unique_pcs_used_that_day > 1) return 'new_or_second_device';
  return 'heavy_use';
}

function falseAlarms(rows, t, users) {
  const flagged = rows.filter((r) => r.risk >= t);
  const sessions = new Set(flagged.map((r) => `${r.user}|${r.sessionStart}`));
  const perUser = new Set(flagged.map((r) => r.user));
  return {
    scored_actions: rows.length,
    flagged_actions: flagged.length,
    flagged_share: rows.length ? round(flagged.length / rows.length) : null,
    sign_outs: sessions.size,
    sign_outs_per_user_per_week: round(sessions.size / users, 2),
    users_affected: `${perUser.size} of ${users}`,
    causes: flagged.reduce((acc, r) => { const c = cause(r); acc[c] = (acc[c] || 0) + 1; return acc; }, {}),
  };
}

function insiderOutcome(rows, t) {
  const attack = rows.filter((r) => r.attack).sort((a, b) => new Date(a.at) - new Date(b.at));
  const first = attack.findIndex((r) => r.risk >= t);
  return {
    attack_actions: attack.length,
    detected: first >= 0,
    actions_until_flag: first >= 0 ? first + 1 : null,
    minutes_until_flag: first >= 0 ? round((new Date(attack[first].at) - new Date(attack[0].at)) / 60000, 1) : null,
    highest_score: attack.length ? round(Math.max(...attack.map((r) => r.risk))) : null,
  };
}

function analyse(rows, counts) {
  const result = { thresholds: {}, normal_scores: {}, false_alarms: {}, insiders: [], sweep: {} };
  for (const role of ROLES) {
    const calib = rows.filter((r) => r.role === role && r.kind === 'normal' && r.phase === 'calibration').map((r) => r.risk);
    const sorted = calib.slice().sort((a, b) => a - b);
    result.normal_scores[role] = {
      actions: calib.length,
      median: round(quantile(sorted, 0.5)), p90: round(quantile(sorted, 0.9)), p95: round(quantile(sorted, 0.95)),
      p99: round(quantile(sorted, 0.99)), max: round(sorted[sorted.length - 1]),
    };
    const cal = calibrate(calib);
    result.thresholds[role] = { current: CURRENT[role], calibrated: cal, budget_reachable: cal !== null };
    const evalRows = rows.filter((r) => r.role === role && r.kind === 'normal' && r.phase === 'evaluation');
    result.false_alarms[role] = { current: falseAlarms(evalRows, CURRENT[role], counts[role]) };
    if (cal !== null) result.false_alarms[role].calibrated = falseAlarms(evalRows, cal, counts[role]);
    // Week-2 trade-off at every threshold: false sign-outs vs. insiders caught.
    const insiderRows = rows.filter((r) => r.role === role && r.kind === 'insider');
    const insiderTags = [...new Set(insiderRows.map((r) => r.user))];
    result.sweep[role] = [];
    for (let t = 0.3; t <= 1.0001; t = round(t + 0.05, 2)) {
      const fa = falseAlarms(evalRows, t, counts[role]);
      result.sweep[role].push({
        threshold: t, flagged_share: fa.flagged_share, sign_outs_per_user_per_week: fa.sign_outs_per_user_per_week,
        insiders_caught: `${insiderTags.filter((u) => insiderOutcome(insiderRows.filter((r) => r.user === u), t).detected).length} of ${insiderTags.length}`,
      });
    }
  }
  for (const ins of INSIDERS) {
    const r = rows.filter((x) => x.user === `ins-${ins.tag}`);
    result.insiders.push({
      tag: ins.tag, role: ins.role, day: ins.day, scenario: ins.scenario,
      current: insiderOutcome(r, CURRENT[ins.role]),
      calibrated: result.thresholds[ins.role].calibrated === null ? null : insiderOutcome(r, result.thresholds[ins.role].calibrated),
    });
  }
  return result;
}

// ------------------------------------------------------- output
function printSummary(a) {
  const pct = (x) => (x === null ? '-' : `${(x * 100).toFixed(1)}%`);
  console.log(`\nNormal users, calibration week (days 1-${CALIBRATION_DAYS}): risk scores`);
  console.table(Object.fromEntries(ROLES.map((r) => [r, a.normal_scores[r]])));
  console.log(`Thresholds: current vs. calibrated (alert budget ${pct(BUDGET)} of normal actions)`);
  console.table(a.thresholds);
  console.log(`False alarms for normal users, evaluation week (days ${CALIBRATION_DAYS + 1}-${DAYS})`);
  console.table(Object.fromEntries(ROLES.flatMap((r) => Object.keys(a.false_alarms[r]).map((k) => {
    const { causes, ...rest } = a.false_alarms[r][k];
    return [`${r} @ ${k} ${a.thresholds[r][k]}`, { ...rest, causes: JSON.stringify(causes) }];
  }))));
  for (const r of ROLES) {
    console.log(`Week-2 trade-off for ${r}: false sign-outs vs. insiders caught at each threshold`);
    console.table(a.sweep[r]);
  }
  console.log('Scripted insiders (week 2)');
  console.table(a.insiders.map((i) => ({
    insider: i.tag, role: i.role,
    'current: caught': i.current.detected ? `yes, action ${i.current.actions_until_flag}` : 'no',
    'calibrated: caught': !i.calibrated ? '(no calibrated threshold)' : i.calibrated.detected ? `yes, action ${i.calibrated.actions_until_flag}` : 'no',
    'highest score': i.current.highest_score,
  })));
}

function writeFiles(rows, analysis, meta) {
  const dir = path.join(__dirname, '..', 'test', 'results');
  fs.mkdirSync(dir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const base = path.join(dir, `simulation_${stamp}`);
  fs.writeFileSync(`${base}.json`, JSON.stringify({ ...meta, ...analysis }, null, 2));
  const cols = Object.keys(rows[0]);
  fs.writeFileSync(`${base}_actions.csv`, [cols.join(',')].concat(rows.map((r) => cols.map((c) => r[c]).join(','))).join('\n'));
  return base;
}

// ------------------------------------------------------- main
async function main() {
  const started = Date.now();
  await clearSimActivity();
  const counts = { Caregiver: 30, SecurityAuditor: 5, SysAdmin: 3 };
  const users = [];
  // Schedules are generated in a fixed order first, so a seed always gives
  // the same two weeks regardless of how fast the database answers.
  for (const role of ROLES) {
    for (let n = 1; n <= counts[role]; n += 1) {
      const tag = `${{ Caregiver: 'cg', SecurityAuditor: 'aud', SysAdmin: 'adm' }[role]}${String(n).padStart(2, '0')}`;
      const profile = role === 'Caregiver' ? caregiverProfile(n) : null;
      users.push({ tag, role, kind: 'normal', schedule: normalSchedule(role, profile) });
    }
  }
  for (const ins of INSIDERS) {
    const profile = ins.role === 'Caregiver' ? caregiverProfile(1) : null;
    users.push({ tag: `ins-${ins.tag}`, role: ins.role, kind: 'insider', schedule: ins.attack(normalSchedule(ins.role, profile), profile) });
  }
  for (const u of users) u.id = await simUser(u.tag, u.role);

  const total = users.reduce((s, u) => s + u.schedule.reduce((t, x) => t + x.actions.length, 0), 0);
  console.log(`Simulating ${users.length} accounts over ${DAYS} days: ${total} scored actions (seed ${SEED})...`);
  const rows = [];
  let done = 0;
  await inPool(users, 6, async (u) => {
    await replayUser(u, rows);
    done += 1;
    if (done % 5 === 0) console.log(`  ${done}/${users.length} accounts done`);
  });

  const analysis = analyse(rows, counts);
  printSummary(analysis);
  const meta = {
    ranAt: new Date().toISOString(), seed: SEED, alert_budget: BUDGET, days: DAYS, calibration_days: CALIBRATION_DAYS,
    accounts: { normal: counts, insiders: INSIDERS.length }, scored_actions: rows.length,
    seconds: round((Date.now() - started) / 1000, 1),
    method: 'Simulated clock; each action goes through access_requests -> computeFeatures -> ML /score, as in the live app. No emails, revocations or risk_scores rows.',
  };
  const base = writeFiles(rows, analysis, meta);
  console.log(`\nSaved ${base}.json and ${path.basename(base)}_actions.csv`);

  if (!KEEP) {
    await clearSimActivity();
    await db.query(`DELETE FROM users WHERE email LIKE '%@${SIM_DOMAIN}'`);
  }
  await db.pool.end();
}

main().catch(async (err) => {
  console.error('Simulation failed:', err.message);
  await db.pool.end().catch(() => {});
  process.exit(1);
});
