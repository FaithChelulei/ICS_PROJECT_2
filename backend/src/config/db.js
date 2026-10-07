// Single shared PostgreSQL connection pool. Every query in the app goes
// through this — never opens its own client — so connections are reused
// instead of exhausted.
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

pool.on('error', (err) => {
  // A background connection died (e.g. DB restarted). Log it, don't crash —
  // the pool will open a new connection on the next query.
  console.error('Unexpected PostgreSQL pool error:', err.message);
});

module.exports = {
  query: (text, params) => pool.query(text, params),
  pool,
};
