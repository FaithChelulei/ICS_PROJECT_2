// SysAdmin-only: encryption key status + re-encryption.
const express = require('express');
const { authenticate, requirePasswordChanged } = require('../middleware/auth');
const { requirePermission } = require('../middleware/rbac');
const { requireStepUp } = require('../middleware/stepUp');
const asyncHandler = require('../utils/asyncHandler');
const { status, reencrypt } = require('../controllers/encryptionController');

const router = express.Router();

router.use(authenticate, requirePasswordChanged, requirePermission('configure_system_settings'));

router.get('/status', asyncHandler(status));
router.post('/reencrypt', requireStepUp, asyncHandler(reencrypt));

module.exports = router;
