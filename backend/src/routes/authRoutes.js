const express = require('express');
const { login, verifyMfa, logout } = require('../controllers/authController');
const { submitRequest } = require('../controllers/registrationController');
const { authenticate } = require('../middleware/auth');

const router = express.Router();

router.post('/login', login);
router.post('/verify-mfa', verifyMfa);
router.post('/logout', authenticate, logout);
// Public — anyone can ask for an account, nobody gets one without a
// SysAdmin approving it (see adminRoutes.js).
router.post('/register', submitRequest);

module.exports = router;
