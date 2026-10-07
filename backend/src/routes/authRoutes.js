const express = require('express');
const { login, verifyMfa, logout } = require('../controllers/authController');
const { authenticate } = require('../middleware/auth');

const router = express.Router();

router.post('/login', login);
router.post('/verify-mfa', verifyMfa);
router.post('/logout', authenticate, logout);

module.exports = router;
