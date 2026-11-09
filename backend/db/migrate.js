// Applies the numbered SQL files in this folder (001_schema.sql, 002_...)
// in order, each exactly once, and records each in schema_migrations. A
// file that fails is rolled back and stops the run, so there are never
// errors to "ignore".
//
// Run from backend/ as the table owner, not app_user (app_user cannot
// create tables or policies):
//   PowerShell: $env:MIGRATE_DATABASE_URL = "postgres://postgres:<password>@localhost:5432/ics_project_2"
//   bash:       export MIGRATE_DATABASE_URL=postgres://postgres:<password>@localhost:5432/ics_project_2
//   then:       node db/migrate.js
//
// A database set up before this script existed (tables present, no
// schema_migrations table) is recorded as already up to date the first
// time, without running anything; only files added later are applied.
const fs = require('fs');
const path = require('path');
const { Client } = require('pg');

const url = process.env.MIGRATE_DATABASE_URL;
if (!url) {
  console.error('Set MIGRATE_DATABASE_URL to the owner (postgres) connection string first. See the comment at the top of db/migrate.js.');
  process.exit(1);
}

const files = fs.readdirSync(__dirname).filter((f) => /^\d{3}_.+\.sql$/.test(f)).sort();

async function main() {
  const client = new Client({ connectionString: url });
  await client.connect();
  try {
    const { rows: [{ existed }] } = await client.query("SELECT to_regclass('public.schema_migrations') IS NOT NULL AS existed");
    await client.query(`CREATE TABLE IF NOT EXISTS schema_migrations (
      filename   VARCHAR(255) PRIMARY KEY,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`);
    const { rows: [{ legacy }] } = await client.query("SELECT to_regclass('public.users') IS NOT NULL AS legacy");
    if (!existed && legacy) {
      for (const f of files) await client.query('INSERT INTO schema_migrations (filename) VALUES ($1) ON CONFLICT DO NOTHING', [f]);
      console.log(`Existing database found: recorded ${files.length} file(s) as already applied. Nothing was run.`);
      return;
    }

    const { rows } = await client.query('SELECT filename FROM schema_migrations');
    const done = new Set(rows.map((r) => r.filename));
    let applied = 0;
    for (const f of files) {
      if (done.has(f)) continue;
      const sql = fs.readFileSync(path.join(__dirname, f), 'utf8');
      try {
        await client.query('BEGIN');
        await client.query(sql);
        await client.query('INSERT INTO schema_migrations (filename) VALUES ($1)', [f]);
        await client.query('COMMIT');
        console.log(`Applied ${f}`);
        applied += 1;
      } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        throw new Error(`${f} failed and was rolled back: ${err.message}`);
      }
    }
    console.log(applied ? `Done: ${applied} file(s) applied.` : 'Database is up to date.');
  } finally {
    await client.end();
  }
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
