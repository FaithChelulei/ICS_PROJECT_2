// Pulls the two pieces of context the ML risk-scoring features need out of
// an Express request. There is no native way for a web backend to know a
// browser client's "PC name" the way the CERT training data's logon.csv
// did -- this project's stand-in is a custom header the frontend (or test
// script) sets once per device: X-Device-Name. If it's absent, pc_name is
// null and is_own_pc/unique_pcs_used_that_day degrade gracefully (see
// featureComputation.js) rather than crashing the request.
function getPcName(req) {
  const value = req.headers['x-device-name'];
  if (!value) return null;
  const trimmed = String(value).trim();
  return trimmed || null;
}

function getIpAddress(req) {
  return req.ip || (req.socket && req.socket.remoteAddress) || null;
}

module.exports = { getPcName, getIpAddress };
