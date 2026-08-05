/**
 * @file routes/auth.js
 * @description Authentication routes (MPP route lives in index.js).
 */
const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const {
  protect,
  restrictTo,
  verifyGateway,
} = require('../middleware/authMiddleware');
const trackUsage = require('../middleware/trackUsage');

// Guard: fail fast with a clear message if any handler is missing
function assertFn(name, fn) {
  if (typeof fn !== 'function') {
    throw new TypeError(
      `[auth routes] "${name}" is not a function (got ${typeof fn}). ` +
        'Check that the module exports it correctly.'
    );
  }
  return fn;
}

assertFn('protect', protect);
assertFn('verifyGateway', verifyGateway);
assertFn('restrictTo', restrictTo);
assertFn('trackUsage', trackUsage);
assertFn('authController.register', authController.register);
assertFn('authController.login', authController.login);
assertFn('authController.getMe', authController.getMe);
assertFn('authController.getUsage', authController.getUsage);
assertFn('authController.logout', authController.logout);
assertFn('authController.resetUsage', authController.resetUsage);
assertFn('authController.getAllUsers', authController.getAllUsers);
assertFn('authController.updateMe', authController.updateMe);
assertFn('authController.deleteMe', authController.deleteMe);
assertFn('authController.updateUser', authController.updateUser);
assertFn('authController.getUserById', authController.getUserById);

// 1. Unauthenticated routes
router.post('/register', authController.register);
router.post('/login', authController.login);

// Protected routes
router.post('/logout', verifyGateway, protect, authController.logout);

router.get('/me', verifyGateway, protect, authController.getMe);
router.get(
  '/data',
  verifyGateway,
  protect,
  trackUsage,
  (req, res) => {
    res.json({ success: true, data: 'Metered data delivered!' });
  }
);

router.get('/usage', verifyGateway, protect, authController.getUsage);
router.post('/reset-usage', protect, authController.resetUsage);

router.get(
  '/all-users',
  verifyGateway,
  protect,
  restrictTo('admin', 'superadmin'),
  authController.getAllUsers
);
router.patch('/update-me', verifyGateway, protect, authController.updateMe);
router.delete('/delete-me', verifyGateway, protect, authController.deleteMe);

router
  .route('/all-users/:id')
  .patch(
    verifyGateway,
    protect,
    restrictTo('admin', 'superadmin'),
    authController.updateUser
  )
  .get(
    verifyGateway,
    protect,
    restrictTo('admin', 'superadmin'),
    authController.getUserById
  );

module.exports = router;
