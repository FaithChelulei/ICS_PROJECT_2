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

// Sent when a SysAdmin approves a registration request — this is the only
// moment a plaintext password ever exists outside the user's own head, so
// it goes straight to their inbox and nowhere else (never logged, never
// returned in an API response body — see registrationController.js).
async function sendAccountApprovedEmail(toEmail, { fullName, role, tempPassword }) {
  if (!transporter) {
    console.log(`[DEV — no SMTP configured] Account approved for ${toEmail} (${role}). Temp password: ${tempPassword}`);
    return;
  }
  await transporter.sendMail({
    from: process.env.SMTP_FROM,
    to: toEmail,
    subject: 'Your account has been approved',
    text: `Hi ${fullName},

Your request for ${role} access has been approved.

Email: ${toEmail}
Temporary password: ${tempPassword}

Please log in and you will be asked to change this password. If you did not request this account, contact the system administrator immediately.`,
  });
}

async function sendAccountRejectedEmail(toEmail, { fullName, reason }) {
  if (!transporter) {
    console.log(`[DEV — no SMTP configured] Account request rejected for ${toEmail}. Reason: ${reason || '(none given)'}`);
    return;
  }
  await transporter.sendMail({
    from: process.env.SMTP_FROM,
    to: toEmail,
    subject: 'Your account request was not approved',
    text: `Hi ${fullName},

Your request for system access was not approved.${reason ? `\n\nReason: ${reason}` : ''}

If you believe this is a mistake, contact the system administrator.`,
  });
}

// Sent when a SysAdmin unlocks an account that was locked after the owner
// clicked "This was NOT me" on a risk alert (see riskResponseController.js
// deny() and userManagementController.js). Same one-plaintext-password-
// moment rule as sendAccountApprovedEmail: never logged, never returned
// in an API response, only ever sent here.
async function sendAccountUnlockedEmail(toEmail, { tempPassword }) {
  if (!transporter) {
    console.log(`[DEV — no SMTP configured] Account unlocked for ${toEmail}. New temp password: ${tempPassword}`);
    return;
  }
  await transporter.sendMail({
    from: process.env.SMTP_FROM,
    to: toEmail,
    subject: 'Your account has been unlocked',
    text: `Your account was locked after you reported unrecognized activity. A System Administrator has reviewed and unlocked it.

New temporary password: ${tempPassword}

Please log in and you will be asked to change this password. If you did not request this, contact the system administrator immediately.`,
  });
}

module.exports = {
  sendMfaCodeEmail,
  sendRiskAlertEmail,
  sendAccountApprovedEmail,
  sendAccountRejectedEmail,
  sendAccountUnlockedEmail,
};
