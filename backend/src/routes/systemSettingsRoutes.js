// SysAdmin-only: the settings that can be changed on screen.
const express = require('express');
const { authenticate, requirePasswordChanged } = require('../middleware/auth');
const { requirePermission } = require('../middleware/rbac');
const { requireStepUp } = require('../middleware/stepUp');
const asyncHandler = require('../utils/asyncHandler');
const { list, update } = require('../controllers/systemSettingsController');

const router = express.Router();

router.use(authenticate, requirePasswordChanged, requirePermission('configure_system_settings'));

router.get('/', asyncHandler(list));
router.post('/:key', requireStepUp, asyncHandler(update));

module.exports = router;
