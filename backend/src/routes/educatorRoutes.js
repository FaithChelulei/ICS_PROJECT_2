// The Educator's routes: ask for access to a child (by name), list the
// children shared with me, and read one shared child's records. Read-only
// by design (SOFIA: "Educator (Optional, Read-Only)").
const express = require('express');
const rateLimit = require('express-rate-limit');
const { authenticate, requirePasswordChanged } = require('../middleware/auth');
const { requirePermission } = require('../middleware/rbac');
const validateIdParam = require('../middleware/validateIdParam');
const asyncHandler = require('../utils/asyncHandler');
const { logAction } = require('../utils/auditLog');
const { requestAccess, listMine, viewRecords } = require('../controllers/educatorAccessController');

const router = express.Router();
router.use(authenticate, requirePasswordChanged);
router.param('childProfileId', validateIdParam);

// Asking is capped at 30 requests a day per educator (enough for a whole
// class), each one logged, so an educator account cannot be used to sweep
// through names or pester parents.
const requestLimit = rateLimit({
  windowMs: 24 * 60 * 60 * 1000,
  limit: 30,
  keyGenerator: (req) => `user:${req.user.id}`,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  handler: async (req, res) => {
    await logAction({ userId: req.user.id, action: 'child_access_request_rate_limited', detail: 'limit=30/day' });
    res.status(429).json({ error: 'You can send 30 requests a day. Try again tomorrow.', code: 'ACCESS_REQUEST_RATE_LIMITED' });
  },
});

router.post('/access-requests', requirePermission('request_child_access'), requestLimit, asyncHandler(requestAccess));
router.get('/children', requirePermission('view_shared_child_records'), asyncHandler(listMine));
router.get('/children/:childProfileId/records', requirePermission('view_shared_child_records'), asyncHandler(viewRecords));

module.exports = router;
