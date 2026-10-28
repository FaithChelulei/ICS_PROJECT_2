// Public -- no authenticate middleware (see riskResponseController.js for
// why: the session behind these links was already force-revoked).
const express = require('express');
const asyncHandler = require('../utils/asyncHandler');
const { confirm, deny } = require('../controllers/riskResponseController');

const router = express.Router();

router.get('/:riskScoreId/confirm', asyncHandler(confirm));
router.get('/:riskScoreId/deny', asyncHandler(deny));

module.exports = router;
