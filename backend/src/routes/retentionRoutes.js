// SysAdmin-only: data retention status + anonymising archived profiles past
// the retention period.
const express = require('express');
const { authenticate, requirePasswordChanged } = require('../middleware/auth');
const { requirePermission } = require('../middleware/rbac');
const asyncHandler = require('../utils/asyncHandler');
const { status, apply } = require('../controllers/retentionController');

const router = express.Router();

router.use(authenticate, requirePasswordChanged, requirePermission('configure_system_settings'));

router.get('/status', asyncHandler(status));
router.post('/apply', asyncHandler(apply));

module.exports = router;
