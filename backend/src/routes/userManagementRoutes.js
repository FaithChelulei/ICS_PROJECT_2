// SysAdmin account-recovery routes. Separate from adminRoutes.js (which
// gates on 'manage_registration_requests') because these gate on the
// distinct 'manage_users' permission -- both happen to belong to SysAdmin
// today, but they're conceptually different capabilities.
const express = require('express');
const { authenticate, requirePasswordChanged } = require('../middleware/auth');
const { requirePermission } = require('../middleware/rbac');
const { requireStepUp } = require('../middleware/stepUp');
const asyncHandler = require('../utils/asyncHandler');
const { listUsers, listLockedUsers, unlockAccount, changeRole } = require('../controllers/userManagementController');
const validateIdParam = require('../middleware/validateIdParam');

const router = express.Router();

router.use(authenticate, requirePasswordChanged, requirePermission('manage_users'));
router.param('id', validateIdParam);

router.get('/', asyncHandler(listUsers));
router.get('/locked', asyncHandler(listLockedUsers));
router.post('/:id/unlock', asyncHandler(unlockAccount));
router.post('/:id/role', requirePermission('manage_roles'), requireStepUp, asyncHandler(changeRole));

module.exports = router;
