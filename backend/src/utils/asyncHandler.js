// Express 4 does not catch a rejected promise thrown inside an async route
// handler -- without this, a DB error or a decryption failure anywhere
// that forgot its own try/catch just hangs the request forever (the
// client eventually sees "Failed to fetch") and logs an unhandled
// rejection warning instead of a clean 500. Wrap every async handler with
// this so any rejection reaches Express's error middleware in app.js.
module.exports = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
