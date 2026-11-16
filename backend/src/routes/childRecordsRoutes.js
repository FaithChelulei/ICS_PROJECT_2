// Every route here requires a valid session (authenticate) AND the
// matching permission for the user's role (requirePermission). Try hitting
// these as a SecurityAuditor test account and you should get a clean 403.
const express = require('express');
const { authenticate, requirePasswordChanged } = require('../middleware/auth');
const { requirePermission } = require('../middleware/rbac');
const asyncHandler = require('../utils/asyncHandler');
const validateIdParam = require('../middleware/validateIdParam');
const {
  exportMyData,
  createChildProfile,
  updateChildDetails,
  archiveChild,
  restoreChild,
  listMyChildren,
  submitRecord,
  listRecords,
} = require('../controllers/childRecordsController');
const { getConsent, setConsent } = require('../controllers/consentController');
const access = require('../controllers/educatorAccessController');

const router = express.Router();

router.use(authenticate, requirePasswordChanged);
router.param('childProfileId', validateIdParam);

router.post('/', requirePermission('create_child_profile'), asyncHandler(createChildProfile));
router.get('/', requirePermission('view_own_child_records'), asyncHandler(listMyChildren));
// "Download my data" (DPIA G6). Registered before the /:childProfileId routes.
router.get('/export', requirePermission('view_own_child_records'), asyncHandler(exportMyData));
// Teachers' access to this caregiver's children ("Who can see my child").
// Registered before the /:childProfileId routes.
router.get('/access', requirePermission('manage_child_access'), asyncHandler(access.listForCaregiver));
router.post('/access/:accessId/decision', requirePermission('manage_child_access'), asyncHandler(access.decide));
router.post('/access/:accessId/revoke', requirePermission('manage_child_access'), asyncHandler(access.revoke));
router.patch('/:childProfileId', requirePermission('correct_own_child_details'), asyncHandler(updateChildDetails));
router.post('/:childProfileId/archive', requirePermission('archive_own_child_profile'), asyncHandler(archiveChild));
router.post('/:childProfileId/restore', requirePermission('archive_own_child_profile'), asyncHandler(restoreChild));
router.post('/:childProfileId/records', requirePermission('submit_developmental_record'), asyncHandler(submitRecord));
router.get('/:childProfileId/records', requirePermission('view_own_child_records'), asyncHandler(listRecords));
router.get('/:childProfileId/consent', requirePermission('manage_own_consent'), asyncHandler(getConsent));
router.post('/:childProfileId/consent', requirePermission('manage_own_consent'), asyncHandler(setConsent));

module.exports = router;
