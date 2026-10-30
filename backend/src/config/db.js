// Single shared PostgreSQL connection pool. Every query in the app goes
// through this — never opens its own client — so connections are reused
// instead of exhausted.
//
// Row-level security (db/migration_rls.sql): the child-data tables only
// return rows the requesting user may see. Postgres learns WHO is asking
// from two transaction-local settings, app.user_id and app.role, which this
// module sets on every query made while a request context is active (see
// middleware/auth.js). No context = no settings = the policies return no
// child rows at all (deny by default).
const { AsyncLocalStorage } = require('async_hooks');
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

pool.on('error', (err) => {
  // A background connection died (e.g. DB restarted). Log it, don't crash —
  // the pool will open a new connection on the next query.
  console.error('Unexpected PostgreSQL pool error:', err.message);
});

// { userId, role } of the user the current request is running as.
const requestContext = new AsyncLocalStorage();

// Runs fn with every query inside it attributed to this user.
function runAs(user, fn) {
  return requestContext.run({ userId: user.userId ?? user.id, role: user.role }, fn);
}

// Maintenance that legitimately needs every child row (re-encrypting all
// data under a new key, CLI tools). Deliberately explicit, so it can only
// happen where code asks for it by name.
function runAsSystem(fn) {
  return requestContext.run({ userId: null, role: 'System' }, fn);
}

async function applyContext(client, ctx) {
  // is_local = true: the settings vanish at COMMIT/ROLLBACK, so a pooled
  // connection never carries one user's identity into the next query.
  await client.query(
    "SELECT set_config('app.user_id', $1, true), set_config('app.role', $2, true)",
    [ctx.userId == null ? '' : String(ctx.userId), ctx.role]
  );
}

// Runs fn(client) inside one transaction, with the request's identity
// applied, committing on success and rolling back on any error.
async function transaction(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const ctx = requestContext.getStore();
    if (ctx) await applyContext(client, ctx);
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

function query(text, params) {
  // Outside a request (start-up, unauthenticated routes) there is no
  // identity to apply -- a plain pooled query, which row-level security
  // treats as "nobody" on the child-data tables.
  if (!requestContext.getStore()) return pool.query(text, params);
  return transaction((client) => client.query(text, params));
}

module.exports = {
  query,
  transaction,
  runAs,
  runAsSystem,
  pool,
};
