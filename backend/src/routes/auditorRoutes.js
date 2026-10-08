const express = require('express');
const { authenticate } = require('../middleware/auth');
const { requirePermission } = require('../middleware/rbac');
const { listFlagged, reviewFlagged } = require('../controllers/auditorController');

const router = express.Router();

router.use(authenticate);

router.get('/flagged-sessions', requirePermission('view_flagged_sessions'), listFlagged);
router.post('/flagged-sessions/:riskScoreId/review', requirePermission('review_risk_scores'), reviewFlagged);

module.exports = router;
