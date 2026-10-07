// Role-based access control. One permission set per role, checked at every
// data request — not just at login — per proposal 3.3.1's functional
// requirement "enforcing role-based access control at every data request".

const PERMISSIONS = {
  Caregiver: [
    'create_child_profile',
    'view_own_child_records',
    'submit_developmental_record',
    'manage_own_consent',
  ],
  SecurityAuditor: [
    'view_flagged_sessions',
    'review_risk_scores',
    'view_audit_log',
  ],
  SysAdmin: [
    'manage_users',
    'manage_roles',
    'configure_system_settings',
    'view_audit_log',
  ],
};

// Express middleware factory: requirePermission('submit_developmental_record')
// Usage: router.post('/records', authenticate, requirePermission('submit_developmental_record'), handler)
function requirePermission(permission) {
  return (req, res, next) => {
    const role = req.user && req.user.role; // set by the auth middleware
    const allowed = PERMISSIONS[role] || [];

    if (!allowed.includes(permission)) {
      return res.status(403).json({
        error: `Role '${role}' does not have permission '${permission}'`,
      });
    }
    next();
  };
}

module.exports = { PERMISSIONS, requirePermission };
