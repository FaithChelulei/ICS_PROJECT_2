// Every route here requires a valid session (authenticate) AND the
// matching permission for the user's role (requirePermission). Try hitting
// these as a SecurityAuditor test account and you should get a clean 403.
const express = require('express');
const { authenticate } = require('../middleware/auth');
const { requirePermission } = require('../middleware/rbac');
const {
  createChildProfile,
  listMyChildren,
  submitRecord,
  listRecords,
} = require('../controllers/childRecordsController');

const router = express.Router();

router.use(authenticate);

router.post('/', requirePermission('create_child_profile'), createChildProfile);
router.get('/', requirePermission('view_own_child_records'), listMyChildren);
router.post('/:childProfileId/records', requirePermission('submit_developmental_record'), submitRecord);
router.get('/:childProfileId/records', requirePermission('view_own_child_records'), listRecords);

module.exports = router;
