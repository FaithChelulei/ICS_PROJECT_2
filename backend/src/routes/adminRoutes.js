// SysAdmin-only routes. Every route here requires both a valid session
// and the 'manage_registration_requests' permission — try hitting these
// with a Caregiver or SecurityAuditor token and expect a 403.
const express = require('express');
const { authenticate, requirePasswordChanged } = require('../middleware/auth');
const { requirePermission } = require('../middleware/rbac');
const asyncHandler = require('../utils/asyncHandler');
const {
  listRequests,
  approveRequest,
  rejectRequest,
} = require('../controllers/registrationController');

const router = express.Router();

router.use(authenticate, requirePasswordChanged, requirePermission('manage_registration_requests'));

router.get('/registration-requests', asyncHandler(listRequests));
router.post('/registration-requests/:id/approve', asyncHandler(approveRequest));
router.post('/registration-requests/:id/reject', asyncHandler(rejectRequest));

module.exports = router;
