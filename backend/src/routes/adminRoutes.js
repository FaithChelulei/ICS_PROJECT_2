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
const { adminOverview } = require('../controllers/overviewController');
const validateIdParam = require('../middleware/validateIdParam');
const { requireStepUp } = require('../middleware/stepUp');
const cases = require('../controllers/accountCaseController');
const approvals = require('../controllers/approvalsController');
const weeklyReview = require('../controllers/weeklyReviewController');

const router = express.Router();

router.use(authenticate, requirePasswordChanged, requirePermission('manage_registration_requests'));
router.param('id', validateIdParam);

router.get('/overview', asyncHandler(adminOverview));
router.get('/registration-requests', asyncHandler(listRequests));
router.post('/registration-requests/:id/approve', asyncHandler(approveRequest));
router.post('/registration-requests/:id/reject', asyncHandler(rejectRequest));

// Two-person approval for re-encryption and anonymising.
router.get('/approvals', requirePermission('approve_powerful_actions'), asyncHandler(approvals.list));
router.post('/approvals', requirePermission('approve_powerful_actions'), requireStepUp, asyncHandler(approvals.request));
router.post('/approvals/:id/approve', requirePermission('approve_powerful_actions'), requireStepUp, asyncHandler(approvals.approve));
router.post('/approvals/:id/reject', requirePermission('approve_powerful_actions'), requireStepUp, asyncHandler(approvals.reject));

// "Take action" cases from the weekly review (db/013): pause until
// verified, then verified or access removed. Password asked again.
router.get('/cases', asyncHandler(cases.listCases));
router.post('/cases/:caseId/pause', requireStepUp, asyncHandler(cases.pause));
router.post('/cases/:caseId/decision', requireStepUp, asyncHandler(cases.decide));

// Layer 2: System Administrators review the Security Auditors' weeks.
router.get('/weekly-review', requirePermission('review_auditor_weeks'), asyncHandler(weeklyReview.list));
router.get('/weekly-review/:id', requirePermission('review_auditor_weeks'), asyncHandler(weeklyReview.detail));
router.post('/weekly-review/:id/decision', requirePermission('review_auditor_weeks'), asyncHandler(weeklyReview.decide));

module.exports = router;
