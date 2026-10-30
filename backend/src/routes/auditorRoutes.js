const express = require('express');
const { authenticate, requirePasswordChanged } = require('../middleware/auth');
const { requirePermission } = require('../middleware/rbac');
const asyncHandler = require('../utils/asyncHandler');
const { listFlagged, reviewFlagged, recordBreachDecision } = require('../controllers/auditorController');
const { listAuditLog } = require('../controllers/auditLogController');
const { downloadReport } = require('../controllers/reportsController');

const router = express.Router();

router.use(authenticate, requirePasswordChanged);

router.get('/flagged-sessions', requirePermission('view_flagged_sessions'), asyncHandler(listFlagged));
router.post('/flagged-sessions/:riskScoreId/review', requirePermission('review_risk_scores'), asyncHandler(reviewFlagged));
router.post('/flagged-sessions/:riskScoreId/breach-decision', requirePermission('review_risk_scores'), asyncHandler(recordBreachDecision));
router.get('/audit-log', requirePermission('view_audit_log'), asyncHandler(listAuditLog));
router.get('/reports/:report', requirePermission('export_reports'), asyncHandler(downloadReport));

module.exports = router;
