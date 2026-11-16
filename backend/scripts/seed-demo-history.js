// Demo history for the weekly review ("People to Review")
// =======================================================
// The weekly review compares each person with their own past weeks, so on a
// new install its list is empty until weeks of real use have built up. This
// script gives a demonstration something to show: a small cast of MADE-UP
// accounts (names end in "(demo)", e-mail addresses on a .test domain that
// cannot receive mail, and no usable password, so nobody can sign in as
// them) with five weeks of ordinary activity, replayed with a past clock
// through the live risk engine -- every action is logged, its features
// computed and scored by the real models, exactly as if it had happened
// then. Real accounts are never touched.
//
// Two of the cast quietly change in the last ten days, the way an insider
// who is careful not to be signed out would:
//   - David Mwangi (educator, a teacher parents have shared their children
//     with) reads about three times his usual number of children's records,
//     from his usual laptop, in school hours.
//   - Peter Kamau (security auditor) opens about three times his usual
//     number of audit-log pages and reports, from his usual office PC.
// Neither is fast enough to be signed out by layer 1. The weekly review
// should list both: David on the auditors' "People to Review" page, Peter
// on the administrators' "Auditor Reviews" page. Everyone else should not
// be listed.
//
// Run from backend/ with the database and the ML service running
// (the backend API itself is not needed):
//   npm run demo:history            create (or re-create) the demo history
//   npm run demo:history -- --remove   delete the demo accounts and all their rows
//   npm run demo:history -- --insiders-only   only the two quiet insiders
//                                    (David and Peter), no ordinary cast, so
//                                    the lists show the real accounts plus them
// Re-run it on the day before a demonstration: the change is placed in the
// last ten days, so both this week and last week show it.
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
// No e-mail for made-up accounts: with SMTP switched off the mailer only
// writes to the console (and the cast is designed never to be flagged).
delete process.env.SMTP_HOST;
delete process.env.SMTP_USER;

const db = require('../src/config/db');
const { recordAndScore, logAccessRequest } = require('../src/services/riskEngine');
const { refreshWeek, weekStartOf, localDate } = require('../src/services/weeklyReview');

const DOMAIN = 'demo-history.childguard.test';
const REMOVE = process.argv.includes('--remove');
const INSIDERS_ONLY = process.argv.includes('--insiders-only');
const HISTORY_WEEKS = 5;
const CHANGE_DAYS = 10;
const DAY_MS = 24 * 60 * 60 * 1000;

// ------------------------------------------------- seeded random numbers
let rngState = 20261111;
function rand() { // mulberry32, so every run gives the same history
  rngState = (rngState + 0x6d2b79f5) >>> 0;
  let t = rngState;
  t = Math.imul(t ^ (t >>> 15), t | 1);
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
}
const between = (a, b) => a + rand() * (b - a);
const intBetween = (a, b) => Math.floor(between(a, b + 1));
function pick(weighted) {
  const total = weighted.reduce((s, [, w]) => s + w, 0);
  let r = rand() * total;
  for (const [v, w] of weighted) { if ((r -= w) <= 0) return v; }
  return weighted[weighted.length - 1][0];
}

const CAREGIVER = [['view_own_child_records', 70], ['submit_developmental_record', 25], ['correct_child_details', 5]];
const AUDITOR = [['review_flagged_session', 45], ['view_audit_log', 40], ['export_report', 15]];
const EDUCATOR = [['view_shared_child_records', 1]];
const ADMIN = [['approve_registration', 55], ['unlock_account', 30], ['reject_registration', 15]];

// The cast. hour = usual start (24h), days = 'all' or 'weekdays',
// active = chance of using the system on such a day, count = [min, max]
// actions, gap = minutes between actions, change = multiplier in the
// last CHANGE_DAYS days.
const CAST = [
  { tag: 'amina', name: 'Amina Wanjiru (demo)', role: 'Caregiver', hour: 8, days: 'all', active: 0.7, count: [2, 4], gap: [3, 7], actions: CAREGIVER, devices: ['laptop'] },
  { tag: 'brian', name: 'Brian Otieno (demo)', role: 'Caregiver', hour: 12.5, days: 'all', active: 0.6, count: [1, 4], gap: [3, 8], actions: CAREGIVER, devices: ['laptop'] },
  { tag: 'grace', name: 'Grace Chebet (demo)', role: 'Caregiver', hour: 17.5, days: 'all', active: 0.65, count: [2, 3], gap: [4, 8], actions: CAREGIVER, devices: ['laptop'] },
  { tag: 'david', name: 'David Mwangi (demo)', role: 'Educator', hour: 9.5, days: 'weekdays', active: 0.9, count: [2, 4], gap: [7, 10], actions: EDUCATOR, devices: ['laptop'], change: 3 },
  { tag: 'mary', name: 'Mary Wambui (demo)', role: 'Educator', hour: 10.5, days: 'weekdays', active: 0.85, count: [2, 5], gap: [5, 9], actions: EDUCATOR, devices: ['laptop'] },
  { tag: 'esther', name: 'Esther Njeri (demo)', role: 'Caregiver', hour: 18, days: 'all', active: 0.6, count: [1, 3], gap: [3, 7], actions: CAREGIVER, devices: ['laptop'] },
  { tag: 'faraji', name: 'Faraji Hassan (demo)', role: 'Caregiver', hour: 13, days: 'all', active: 0.65, count: [2, 4], gap: [3, 7], actions: CAREGIVER, devices: ['laptop'] },
  { tag: 'joyce', name: 'Joyce Achieng (demo)', role: 'SecurityAuditor', hour: 9, days: 'weekdays', active: 0.9, count: [3, 5], gap: [4, 9], actions: AUDITOR, devices: ['office-pc'] },
  { tag: 'peter', name: 'Peter Kamau (demo)', role: 'SecurityAuditor', hour: 10, days: 'weekdays', active: 0.9, count: [2, 4], gap: [6, 9], actions: [['view_audit_log', 2], ['review_flagged_session', 1], ['export_report', 1]], devices: ['office-pc'], change: 3 },
  { tag: 'samuel', name: 'Samuel Kiprop (demo)', role: 'SysAdmin', hour: 10, days: 'weekdays', active: 0.9, count: [1, 3], gap: [3, 6], actions: ADMIN, devices: ['admin-pc'] },
];

const email = (tag) => `${tag}@${DOMAIN}`;

async function account(c) {
  const { rows: roleRows } = await db.query('SELECT id FROM roles WHERE name = $1', [c.role]);
  // '!' is not a bcrypt hash, so no password can ever match: the account
  // exists only to own the demonstration history. An account kept by an
  // earlier --remove (see removeDemo) is reused.
  const { rows } = await db.query(
    `INSERT INTO users (email, full_name, username, password_hash, role_id, mfa_required, must_change_password, is_locked, created_at)
     VALUES ($1, $2, $3, '!', $4, $5, FALSE, FALSE, $6)
     ON CONFLICT (email) DO UPDATE SET full_name = EXCLUDED.full_name, password_hash = '!', is_locked = FALSE, locked_reason = NULL
     RETURNING id`,
    [email(c.tag), c.name, `demo.${c.tag}`, roleRows[0].id, c.role !== 'Caregiver', new Date(Date.now() - (HISTORY_WEEKS * 7 + 7) * DAY_MS)]
  );
  return rows[0].id;
}

// Removes everything the script made. Demo accounts never write to the audit
// log (they are never flagged and never sign in), so they can be deleted;
// if one ever did, it is locked and kept instead, because the audit log
// cannot be changed.
async function removeDemo() {
  const ids = `(SELECT id FROM users WHERE email LIKE '%@${DOMAIN}')`;
  const { rows: before } = await db.query(`SELECT id, email FROM users WHERE email LIKE '%@${DOMAIN}'`);
  await db.query(`DELETE FROM weekly_reviews WHERE user_id IN ${ids}`);
  await db.query(`DELETE FROM access_requests WHERE user_id IN ${ids}
                  AND id NOT IN (SELECT access_request_id FROM audit_log WHERE access_request_id IS NOT NULL)`);
  await db.query(`DELETE FROM sessions WHERE user_id IN ${ids}
                  AND id NOT IN (SELECT session_id FROM access_requests WHERE session_id IS NOT NULL)`);
  let removed = 0;
  let locked = 0;
  for (const u of before) {
    try {
      await db.query('DELETE FROM users WHERE id = $1', [u.id]);
      removed += 1;
    } catch {
      await db.query("UPDATE users SET is_locked = TRUE, locked_reason = 'Demonstration history (removed)' WHERE id = $1", [u.id]);
      locked += 1;
    }
  }
  return { removed, locked };
}

function plan(c, days, changeFrom) {
  const out = [];
  for (const day of days) {
    const weekday = day.getDay() >= 1 && day.getDay() <= 5;
    if (c.days === 'weekdays' && !weekday) continue;
    const changed = c.change && day >= changeFrom;
    if (!changed && rand() > c.active) continue;
    const start = new Date(day);
    start.setMinutes(Math.round((c.hour + between(-0.4, 0.4)) * 60));
    let n = intBetween(c.count[0], c.count[1]);
    // A real rise is uneven from day to day, not exactly 3x every day.
    // At most 10 a day: a quiet insider stays under the instant check's
    // radar, which is the point of the demonstration.
    if (changed) n = Math.min(10, Math.max(n + 2, Math.round(n * c.change + between(-2, 1))));
    const device = c.devices.length > 1 && rand() < 0.3 ? c.devices[1] : c.devices[0];
    const times = [];
    let t = new Date(start.getTime() + between(0.5, 2) * 60000);
    for (let i = 0; i < n; i += 1) {
      times.push({ type: pick(c.actions), at: t });
      t = new Date(t.getTime() + between(c.gap[0], c.gap[1]) * 60000);
    }
    if (times[times.length - 1].at > new Date()) continue; // nothing in the future
    out.push({ start, device, times, changed });
  }
  return out;
}

async function replay(c, userId, sessions) {
  let scored = 0;
  let flagged = 0;
  for (const s of sessions) {
    // Each replayed sign-in ends with a sign-out, so none looks still open.
    const { rows } = await db.query(
      "INSERT INTO sessions (user_id, issued_at, revoked_at, revoked_reason) VALUES ($1, $2, $3, 'user_logout') RETURNING id",
      [userId, s.start, s.times[s.times.length - 1].at]);
    const base = { userId, pcName: `demo-${c.tag}-${s.device}`, ipAddress: '127.0.0.1', sessionId: rows[0].id };
    await logAccessRequest({ ...base, actionType: 'login', now: s.start });
    const listing = { Caregiver: 'list_own_children', Educator: 'list_shared_children' }[c.role] || 'view_overview';
    await logAccessRequest({ ...base, actionType: listing, now: new Date(s.start.getTime() + 20000) });
    for (const a of s.times) {
      const r = await recordAndScore({ ...base, role: c.role, actionType: a.type, now: a.at });
      if (!r.scored) throw new Error('The ML service did not answer -- start ml/service/app.py first');
      scored += 1;
      if (r.flagged) { flagged += 1; break; } // a signed-out session ends there, as it would live
    }
  }
  return { scored, flagged };
}

async function main() {
  const quiet = console.log;
  console.log = (...a) => { if (!String(a[0]).startsWith('[DEV')) quiet(...a); };

  const cleared = await removeDemo();
  if (REMOVE) {
    quiet(`Removed ${cleared.removed} demo account(s) and their activity${cleared.locked ? `; ${cleared.locked} locked and kept (they appear in the audit log)` : ''}.`);
    return;
  }
  if (cleared.removed || cleared.locked) quiet(`Cleared the previous demo history (${cleared.removed} account(s)).`);

  const today = new Date();
  const monday = weekStartOf(today);
  const first = new Date(monday.getTime() - HISTORY_WEEKS * 7 * DAY_MS);
  const days = [];
  for (let t = new Date(first); t <= today; t = new Date(t.getTime() + DAY_MS)) days.push(new Date(t));
  const changeFrom = new Date(today.getTime() - CHANGE_DAYS * DAY_MS);
  changeFrom.setHours(0, 0, 0, 0);

  const people = INSIDERS_ONLY ? CAST.filter((c) => c.change) : CAST;
  quiet(`Replaying ${days.length} days (${localDate(first)} to ${localDate(today)}) for ${people.length} made-up account(s)${INSIDERS_ONLY ? ' (the quiet insiders only)' : ''} through the live risk engine...`);
  const summary = [];
  for (const c of people) {
    const id = await account(c);
    const sessions = plan(c, days, changeFrom);
    const r = await replay(c, id, sessions);
    summary.push({ id, ...c, ...r, days: sessions.length });
    quiet(`  ${c.name.padEnd(24)} ${c.role.padEnd(15)} ${String(sessions.length).padStart(3)} days, ${String(r.scored).padStart(3)} scored actions${r.flagged ? `, ${r.flagged} signed out by layer 1` : ''}${c.change ? `  <- ${c.change}x usual in the last ${CHANGE_DAYS} days` : ''}`);
  }

  // Score every week that has demo activity, as the hourly job does for the current one.
  quiet('Scoring the weeks (the same code as the hourly weekly review)...');
  for (let w = HISTORY_WEEKS; w >= 0; w -= 1) {
    const r = await refreshWeek(new Date(monday.getTime() - w * 7 * DAY_MS));
    if (!r.ok) throw new Error(`weekly scoring failed: ${r.error}`);
  }

  const { rows } = await db.query(
    `SELECT u.full_name, wr.week_label, wr.role_name, wr.score, wr.above_limit, wr.rule_flags, wr.reasons
     FROM weekly_reviews wr JOIN users u ON u.id = wr.user_id
     WHERE u.email LIKE '%@${DOMAIN}' AND wr.week_start >= $1 ORDER BY wr.week_start, wr.score DESC`,
    [localDate(new Date(monday.getTime() - 7 * DAY_MS))]
  );
  for (const label of [...new Set(rows.map((r) => r.week_label))]) {
    quiet(`\nWeek ${label}:`);
    for (const r of rows.filter((x) => x.week_label === label)) {
      const listed = r.above_limit || (r.rule_flags || []).length > 0;
      quiet(`  ${listed ? 'LISTED    ' : 'not listed'}  ${r.full_name.padEnd(24)} ${r.role_name.padEnd(15)} index ${Number(r.score).toFixed(2)}  ${(r.reasons || []).slice(0, 2).map((x) => x.code).join(', ')}${(r.rule_flags || []).length ? `  rule: ${r.rule_flags.map((f) => f.code).join(', ')}` : ''}`);
    }
  }
  // The current week may be only a day or two old (the change half needs at
  // least three days of it), so say which week shows the two quiet changes.
  const changers = CAST.filter((c) => c.change).map((c) => c.name);
  const shows = [...new Set(rows.map((r) => r.week_label))].reverse().find((label) => changers.every((n) =>
    rows.some((r) => r.week_label === label && r.full_name === n && (r.above_limit || (r.rule_flags || []).length))));
  quiet(shows
    ? `\nFor the demonstration open the week ${shows} (use "Previous week" at the top of the page if it is not the week shown).`
    : '\nThe quiet changes are not on the list yet: re-run this tomorrow, when the current week has more days.');
  const flags = summary.reduce((s, x) => s + x.flagged, 0);
  quiet(`\nDone. ${flags ? `${flags} action(s) were signed out by layer 1 -- see above.` : 'No demo account was signed out by layer 1.'}`);
  quiet('Sign in as a Security Auditor and open "People to Review"; as a System Administrator, open "Auditor Reviews".');
  quiet('Remove it all after the demonstration with:  npm run demo:history -- --remove');
}

main()
  .catch((err) => { console.error('Demo history failed:', err.message); process.exitCode = 1; })
  .finally(() => db.pool.end().catch(() => {}));
