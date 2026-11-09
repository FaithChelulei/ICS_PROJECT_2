// The reason typed for a security-relevant change (threshold, role, setting).
// Returns the tidied text, or null if it is missing or the wrong length.
function cleanReason(value) {
  if (typeof value !== 'string') return null;
  const reason = value.trim();
  return reason.length >= 10 && reason.length <= 500 ? reason : null;
}

module.exports = { cleanReason };
