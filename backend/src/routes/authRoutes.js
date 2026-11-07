const express = require('express');
const rateLimit = require('express-rate-limit');
const { login, verifyMfa, logout, me, changePassword } = require('../controllers/authController');
const { submitRequest } = require('../controllers/registrationController');
const { authenticate } = require('../middleware/auth');
const asyncHandler = require('../utils/asyncHandler');

const router = express.Router();

// Only the two routes someone could actually brute-force -- NOT /me (it's
// called passively on every page load/refresh, a blanket /auth limit
// would rate-limit normal use out of existence) and not /change-password.
// 20 FAILED attempts per 15 minutes per IP turns guessing a 6-digit MFA
// code from "a few hundred requests" into "infeasible in a session".
// Successful logins don't count (skipSuccessfulRequests): only guessing
// should use up the allowance, not a busy legitimate user -- counting every
// login locked a full demo run (several real sign-ins) out after 20.
const authBruteForceLimit = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, skipSuccessfulRequests: true });

router.post('/login', authBruteForceLimit, asyncHandler(login));
router.post('/verify-mfa', authBruteForceLimit, asyncHandler(verifyMfa));
router.post('/logout', authenticate, asyncHandler(logout));
// Deliberately NOT behind requirePasswordChanged -- these are exactly the
// two routes that must stay reachable while that flag is still true.
router.get('/me', authenticate, asyncHandler(me));
router.post('/change-password', authenticate, asyncHandler(changePassword));
// Public — anyone can ask for an account, nobody gets one without a
// SysAdmin approving it (see adminRoutes.js).
router.post('/register', asyncHandler(submitRequest));

module.exports = router;
