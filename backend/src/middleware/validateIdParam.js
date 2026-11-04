// router.param() callback for numeric ids in URLs (:childProfileId,
// :riskScoreId, :id). Rejects anything that isn't a whole number within
// PostgreSQL's integer range with a clean 400, BEFORE any handler or query
// runs. Without it, "/children/abc/records" reached the database as NaN and
// came back as a 500 -- no data leaked and no SQL ran (queries are
// parameterised), but invalid input should be refused at the door.
const PG_INT_MAX = 2147483647;

function validateIdParam(req, res, next, value) {
  if (!/^\d{1,10}$/.test(value) || Number(value) < 1 || Number(value) > PG_INT_MAX) {
    return res.status(400).json({ error: 'Invalid ID in the address' });
  }
  next();
}

module.exports = validateIdParam;
