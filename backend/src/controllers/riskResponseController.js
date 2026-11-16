// Public endpoints behind the "This was me" / "This was NOT me" links in
// the risk-alert email (riskEngine.js -> mailer.js sendRiskAlertEmail).
// Deliberately NOT behind the authenticate middleware: reaching this link
// means the user's session was already force-revoked, so they have no
// valid bearer token to present. The signed token in the URL
// (riskResponseToken.js) proves intent instead.
//
// Opening a link only SHOWS a page (showResponsePage); nothing changes
// until its button is pressed, which POSTs the token back (confirm/deny).
// Mail scanners such as Outlook Safe Links open every link in an email to
// check it, so if a plain GET acted, a scanner could lock an account or
// mark a real attack as "this was me" without the owner ever seeing it.
const db = require('../config/db');
const { verifyRiskResponseToken } = require('../utils/riskResponseToken');
const { logAction } = require('../utils/auditLog');

async function loadRiskScore(riskScoreId) {
  const { rows } = await db.query(
    `SELECT rs.id, rs.owner_response, rs.auditor_status, ar.user_id
     FROM risk_scores rs
     JOIN access_requests ar ON ar.id = rs.access_request_id
     WHERE rs.id = $1`,
    [riskScoreId]
  );
  return rows[0] || null;
}

// The pages opened from the alert e-mail ("This was me" / "This was NOT
// me"), in ChildGuard's own look: cream background, teal, a card. Inline
// styles only (served by the API, outside the website).
function htmlPage(message, extra = '') {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="referrer" content="no-referrer"><title>ChildGuard</title>
<style>
  body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center; background: #FBF6ED; color: #211C16;
         font-family: Inter, "Segoe UI", system-ui, -apple-system, sans-serif; padding: 24px; box-sizing: border-box; }
  .card { width: 100%; max-width: 460px; background: #fff; border: 1px solid #EFE4D0; border-radius: 24px; padding: 36px 32px;
          box-shadow: 0 10px 30px rgba(33, 28, 22, 0.06); text-align: center; }
  .brand { display: inline-flex; align-items: center; gap: 10px; font-weight: 700; font-size: 20px; color: #155242; margin-bottom: 22px; }
  .logo { width: 36px; height: 36px; border-radius: 12px; background: #1F6D52; display: inline-flex; align-items: center; justify-content: center; }
  .logo span { width: 7px; height: 7px; background: #fff; margin: 1px; display: inline-block; border-radius: 2px; }
  .icon { width: 56px; height: 56px; border-radius: 18px; background: #EBF4F0; color: #1F6D52; font-size: 26px; display: flex;
          align-items: center; justify-content: center; margin: 0 auto 16px; }
  p { font-size: 17px; line-height: 1.55; margin: 0 0 20px; }
  button { font: inherit; font-size: 16px; font-weight: 600; color: #fff; background: #1F6D52; border: 0; border-radius: 999px;
           padding: 12px 26px; cursor: pointer; }
  button:hover { background: #155242; }
  .foot { margin-top: 18px; font-size: 13px; color: #374151; }
</style></head><body><div class="card">
<div class="brand"><span class="logo"><span></span><span></span></span>ChildGuard</div>
<div class="icon">&#128274;</div>
<p>${message}</p>${extra}
<div class="foot">This page was opened from a ChildGuard security e-mail.</div>
</div></body></html>`;
}

const escapeHtml = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const ACTIONS = {
  confirm: {
    question: 'Was this you? If you did this yourself, confirm it below. You can then sign in again normally.',
    button: 'Yes, this was me',
  },
  deny: {
    question: 'If you did NOT do this, press the button below. Your account will be locked straight away so nobody can use it, and a System Administrator will help you reset your password.',
    button: 'No, this was NOT me — lock my account',
  },
};

// GET /risk-response/:riskScoreId/:action -- the link in the email. Checks
// the token and shows one button; it never changes anything.
async function showResponsePage(req, res) {
  const riskScoreId = Number(req.params.riskScoreId);
  const action = req.params.action;
  const { token } = req.query;
  res.set('Cache-Control', 'no-store');

  if (!verifyRiskResponseToken(token, riskScoreId, action)) {
    return res.status(403).send(htmlPage('This link is invalid or has expired.'));
  }
  const risk = await loadRiskScore(riskScoreId);
  if (!risk) return res.status(404).send(htmlPage('This alert could not be found.'));
  if (risk.owner_response !== 'pending') {
    return res.send(htmlPage('You already responded to this alert. No further action needed.'));
  }
  const { question, button } = ACTIONS[action];
  return res.send(htmlPage(escapeHtml(question),
    `<form method="post" action="/risk-response/${riskScoreId}/${action}">`
    + `<input type="hidden" name="token" value="${escapeHtml(token)}">`
    + `<button type="submit">${escapeHtml(button)}</button></form>`));
}

// POST /risk-response/:riskScoreId/confirm -- the page's button.
async function confirm(req, res) {
  const riskScoreId = Number(req.params.riskScoreId);
  const token = req.body && req.body.token;
  res.set('Cache-Control', 'no-store');

  if (!verifyRiskResponseToken(token, riskScoreId, 'confirm')) {
    return res.status(403).send(htmlPage('This link is invalid or has expired.'));
  }

  const risk = await loadRiskScore(riskScoreId);
  if (!risk) return res.status(404).send(htmlPage('This alert could not be found.'));

  if (risk.owner_response !== 'pending') {
    return res.send(htmlPage('You already responded to this alert. No further action needed.'));
  }

  await db.query("UPDATE risk_scores SET owner_response = 'confirmed_benign' WHERE id = $1", [riskScoreId]);
  await logAction({
    userId: risk.user_id,
    action: 'risk_response_confirmed_benign',
    detail: `risk_score_id=${riskScoreId}`,
  });

  return res.send(htmlPage(
    'Thanks for confirming. You can log in again normally. This activity has still been logged for routine security review.'
  ));
}

// POST /risk-response/:riskScoreId/deny -- the page's button.
async function deny(req, res) {
  const riskScoreId = Number(req.params.riskScoreId);
  const token = req.body && req.body.token;
  res.set('Cache-Control', 'no-store');

  if (!verifyRiskResponseToken(token, riskScoreId, 'deny')) {
    return res.status(403).send(htmlPage('This link is invalid or has expired.'));
  }

  const risk = await loadRiskScore(riskScoreId);
  if (!risk) return res.status(404).send(htmlPage('This alert could not be found.'));

  if (risk.owner_response !== 'pending') {
    return res.send(htmlPage('You already responded to this alert. No further action needed.'));
  }

  await db.query(
    "UPDATE risk_scores SET owner_response = 'not_me', auditor_status = 'escalated' WHERE id = $1",
    [riskScoreId]
  );
  await db.query(
    "UPDATE users SET is_locked = TRUE, locked_reason = 'Owner reported unrecognized activity -- pending password reset' WHERE id = $1",
    [risk.user_id]
  );
  await logAction({
    userId: risk.user_id,
    action: 'risk_response_not_me_account_locked',
    detail: `risk_score_id=${riskScoreId}`,
  });

  return res.send(htmlPage(
    'Your account has been locked for safety. Contact a System Administrator to reset your password.'
  ));
}

module.exports = { showResponsePage, confirm, deny };
