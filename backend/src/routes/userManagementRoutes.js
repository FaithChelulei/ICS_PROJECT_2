// SysAdmin account-recovery routes. Separate from adminRoutes.js (which
// gates on 'manage_registration_requests') because these gate on the
// distinct 'manage_users' permission -- both happen to belong to SysAdmin
// today, but they're conceptually different capabilities.
const express = require('express');
const { authenticate } = require('../middleware/auth');
const { requirePermission } = require('../middleware/rbac');
const { listLockedUsers, unlockAccount } = require('../controllers/userManagementController');

const router = express.Router();

router.use(authenticate, requirePermission('manage_users'));

router.get('/locked', listLockedUsers);
router.post('/:id/unlock', unlockAccount);

module.exports = router;
