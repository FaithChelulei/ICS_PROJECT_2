// npm run retention:status  -- archived profiles, how many are past the
//                              retention period, how many already anonymised
// npm run retention:apply   -- anonymise the identity of every archived
//                              profile past the period (e.g. from a daily
//                              scheduled task)
// Same logic as Admin > Data Retention. Never prints child data.
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const db = require('../src/config/db');
const { getRetentionStatus, applyRetention } = require('../src/services/retention');
const { logAction } = require('../src/utils/auditLog');

function printStatus(s) {
  console.log(`Retention period: ${s.retentionDays} day(s) after archiving`);
  console.log(`  ${s.archived} archived profile(s), ${s.due} past the period, ${s.anonymised} already anonymised`);
}

(async () => {
  if (process.argv[2] === 'apply') {
    const ids = await applyRetention();
    await logAction({
      userId: null,
      action: 'apply_retention',
      detail: `cli, anonymised=${ids.length}${ids.length ? `, child_profile_ids=${ids.join(',')}` : ''}`,
    });
    console.log(`Anonymised ${ids.length} profile(s)${ids.length ? `: #${ids.join(', #')}` : ''}.`);
  }
  printStatus(await getRetentionStatus());
  await db.pool.end();
})().catch(async (err) => {
  console.error('Failed:', err.message);
  try { await db.pool.end(); } catch { /* ignore */ }
  process.exit(1);
});
