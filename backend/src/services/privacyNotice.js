// KDPA s.29 (duty to notify): people are told how their data will be used
// before it is collected. The notice text lives in the frontend
// (components/PrivacyNotice.jsx); the backend only checks that the form
// carried the CURRENT version, and stores it, so there is a record of which
// notice each account request and each child profile was accepted under.
//
// Changing the notice text = bump this version AND the frontend's.
const PRIVACY_NOTICE_VERSION = '2026-10';

// Returns an error message, or null if the request accepted the current notice.
function checkPrivacyNotice(body) {
  if (body.privacyNoticeVersion !== PRIVACY_NOTICE_VERSION) {
    return 'Please read and accept the privacy notice before continuing.';
  }
  return null;
}

module.exports = { PRIVACY_NOTICE_VERSION, checkPrivacyNotice };
