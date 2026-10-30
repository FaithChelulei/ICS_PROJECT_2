// Every route here requires a valid session (authenticate) AND the
// matching permission for the user's role (requirePermission). Try hitting
// these as a SecurityAuditor test account and you should get a clean 403.
const express = require('express');
const { authenticate, requirePasswordChanged } = require('../middleware/auth');
const { requirePermission } = require('../middleware/rbac');
const asyncHandler = require('../utils/asyncHandler');
const {
  createChildProfile,
  updateChildDetails,
  listMyChildren,
  submitRecord,
  listRecords,
} = require('../controllers/childRecordsController');
const { getConsent, setConsent } = require('../controllers/consentController');

const router = express.Router();

router.use(authenticate, requirePasswordChanged);

router.post('/', requirePermission('create_child_profile'), asyncHandler(createChildProfile));
router.get('/', requirePermission('view_own_child_records'), asyncHandler(listMyChildren));
router.patch('/:childProfileId', requirePermission('correct_own_child_details'), asyncHandler(updateChildDetails));
router.post('/:childProfileId/records', requirePermission('submit_developmental_record'), asyncHandler(submitRecord));
router.get('/:childProfileId/records', requirePermission('view_own_child_records'), asyncHandler(listRecords));
router.get('/:childProfileId/consent', requirePermission('manage_own_consent'), asyncHandler(getConsent));
router.post('/:childProfileId/consent', requirePermission('manage_own_consent'), asyncHandler(setConsent));

module.exports = router;
