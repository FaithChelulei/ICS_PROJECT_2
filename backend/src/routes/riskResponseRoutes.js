// Public -- no authenticate middleware (see riskResponseController.js for
// why: the session behind these links was already force-revoked).
const express = require('express');
const asyncHandler = require('../utils/asyncHandler');
const { showResponsePage, confirm, deny } = require('../controllers/riskResponseController');
const validateIdParam = require('../middleware/validateIdParam');

const router = express.Router();
router.param('riskScoreId', validateIdParam);

// Opening the emailed link only shows a page with one button (a mail
// scanner opening it changes nothing); the button POSTs the token back.
const form = express.urlencoded({ extended: false, limit: '4kb' });
router.get('/:riskScoreId/:action(confirm|deny)', asyncHandler(showResponsePage));
router.post('/:riskScoreId/confirm', form, asyncHandler(confirm));
router.post('/:riskScoreId/deny', form, asyncHandler(deny));

module.exports = router;
