/**
 * @file routes/auth.js
 * @description Authentication routes (MPP route lives in index.js).
 */

const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { restrictTo, verifyGateway } = require('../middleware/auth');
const { protect } = require('../middleware/authMiddleware');

// 1. Unauthenticated routes
router.post('/register', authController.register);
router.post('/login', authController.login);

// Protected routes
router.post('/logout', verifyGateway, protect, authController.logout);

router.get('/me', verifyGateway, protect, authController.getMe);
router.get('/data', verifyGateway, protect, authController.trackUsage, (req, res) => {
  res.json({ success: true, data: 'Metered data delivered!' });
});

router.get('/usage', verifyGateway, protect, authController.getUsage);
router.post('/reset-usage', protect, authController.resetUsage);

router.get('/all-users', verifyGateway, protect, restrictTo('admin', 'superadmin'), authController.getAllUsers);
router.patch('/update-me', verifyGateway, protect, authController.updateMe);
router.delete('/delete-me', verifyGateway, protect, authController.deleteMe);

router.route('/all-users/:id')
  .patch(verifyGateway, protect, restrictTo('admin', 'superadmin'), authController.updateUser)
  .get(verifyGateway, protect, restrictTo('admin', 'superadmin'), authController.getUserById);

module.exports = router;