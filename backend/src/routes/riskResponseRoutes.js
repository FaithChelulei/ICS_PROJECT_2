// Public -- no authenticate middleware (see riskResponseController.js for
// why: the session behind these links was already force-revoked).
const express = require('express');
const asyncHandler = require('../utils/asyncHandler');
const { confirm, deny } = require('../controllers/riskResponseController');
const validateIdParam = require('../middleware/validateIdParam');

const router = express.Router();
router.param('riskScoreId', validateIdParam);

router.get('/:riskScoreId/confirm', asyncHandler(confirm));
router.get('/:riskScoreId/deny', asyncHandler(deny));

module.exports = router;
