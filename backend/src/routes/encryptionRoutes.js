// SysAdmin-only: encryption key status + re-encryption.
const express = require('express');
const { authenticate, requirePasswordChanged } = require('../middleware/auth');
const { requirePermission } = require('../middleware/rbac');
const asyncHandler = require('../utils/asyncHandler');
const { status, reencrypt } = require('../controllers/encryptionController');

const router = express.Router();

router.use(authenticate, requirePasswordChanged, requirePermission('configure_system_settings'));

router.get('/status', asyncHandler(status));
router.post('/reencrypt', asyncHandler(reencrypt));

module.exports = router;
