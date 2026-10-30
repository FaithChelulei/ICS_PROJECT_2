const express = require('express');
const rateLimit = require('express-rate-limit');
const { logAction } = require('../utils/auditLog');
const { authenticate, requirePasswordChanged } = require('../middleware/auth');
const { requirePermission } = require('../middleware/rbac');
const asyncHandler = require('../utils/asyncHandler');
const { listFlagged, reviewFlagged, recordBreachDecision } = require('../controllers/auditorController');
const { listAuditLog } = require('../controllers/auditLogController');
const { downloadReport } = require('../controllers/reportsController');

const router = express.Router();

router.use(authenticate, requirePasswordChanged);

// Hard cap on report downloads per auditor, alongside the risk model. The
// model catches large or fast scraping and off-hours use, but a slow trickle
// of exports scores like a genuinely busy day (docs/RISK_THRESHOLDS.md), so
// a fixed limit covers that gap predictably. Requests rejected for bad
// input don't count. Held in memory: it resets when the backend restarts.
const reportExportLimit = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: Number(process.env.REPORT_EXPORTS_PER_HOUR) || 10,
  keyGenerator: (req) => `user:${req.user.id}`,
  skipFailedRequests: true,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  handler: async (req, res) => {
    await logAction({
      userId: req.user.id,
      action: 'report_export_rate_limited',
      detail: `report=${req.params.report}, limit=${req.rateLimit.limit}/hour`,
    }).catch(() => {});
    res.status(429).json({
      error: `Report download limit reached (${req.rateLimit.limit} per hour). Try again later.`,
      code: 'EXPORT_RATE_LIMITED',
    });
  },
});

router.get('/flagged-sessions', requirePermission('view_flagged_sessions'), asyncHandler(listFlagged));
router.post('/flagged-sessions/:riskScoreId/review', requirePermission('review_risk_scores'), asyncHandler(reviewFlagged));
router.post('/flagged-sessions/:riskScoreId/breach-decision', requirePermission('review_risk_scores'), asyncHandler(recordBreachDecision));
router.get('/audit-log', requirePermission('view_audit_log'), asyncHandler(listAuditLog));
router.get('/reports/:report', requirePermission('export_reports'), reportExportLimit, asyncHandler(downloadReport));

module.exports = router;
