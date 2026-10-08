// Public -- no authenticate middleware (see riskResponseController.js for
// why: the session behind these links was already force-revoked).
const express = require('express');
const { confirm, deny } = require('../controllers/riskResponseController');

const router = express.Router();

router.get('/:riskScoreId/confirm', confirm);
router.get('/:riskScoreId/deny', deny);

module.exports = router;
