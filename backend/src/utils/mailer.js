// Thin wrapper around nodemailer. Used for two things in this system:
// (1) the MFA one-time code during Security Auditor / SysAdmin login,
// (2) the risk-tier "This was me / This was NOT me" confirmation email.
const nodemailer = require('nodemailer');

const smtpConfigured = Boolean(process.env.SMTP_HOST && process.env.SMTP_USER);

const transporter = smtpConfigured
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    })
  : null;

async function sendMfaCodeEmail(toEmail, code) {
  if (!transporter) {
    // Dev fallback: no SMTP configured yet. Log instead of failing, so the
    // MFA flow can still be tested end-to-end before real email is wired up.
    console.log(`[DEV — no SMTP configured] MFA code for ${toEmail}: ${code}`);
    return;
  }
  await transporter.sendMail({
    from: process.env.SMTP_FROM,
    to: toEmail,
    subject: 'Your login verification code',
    text: `Your one-time code is ${code}. It expires in 10 minutes. If you did not request this, ignore this email.`,
  });
}

// Sent automatically the moment a session crosses its role's risk
// threshold (risk_tiers.json: at_or_above_review_threshold_automatic).
// confirmUrl / denyUrl point at the "This was me" / "This was NOT me"
// endpoints built on Friday alongside the risk-response route.
async function sendRiskAlertEmail(toEmail, { timestamp, pcName, actionType, role, confirmUrl, denyUrl }) {
  if (!transporter) {
    console.log(`[DEV — no SMTP configured] Risk alert for ${toEmail}: confirm=${confirmUrl} deny=${denyUrl}`);
    return;
  }
  await transporter.sendMail({
    from: process.env.SMTP_FROM,
    to: toEmail,
    subject: 'Unusual activity on your account — action needed',
    text: `We detected unusual activity on your account and logged you out as a precaution.

Time: ${timestamp}
Device: ${pcName}
Action: ${actionType}
Role: ${role}

If this was you: ${confirmUrl}
If this was NOT you: ${denyUrl}

This session has also been queued for independent review by a Security Auditor.`,
  });
}

module.exports = { sendMfaCodeEmail, sendRiskAlertEmail };
