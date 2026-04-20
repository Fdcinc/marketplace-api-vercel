const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { protect, restrictTo, verifyGateway } = require('../middleware/auth');

// 🔒 GATEWAY PROTECTION
router.use(verifyGateway);

// ──── PUBLIC ROUTES ────
router.post('/register', authController.register);
router.post('/login', authController.login);

// ──── PROTECTED ROUTES ────
router.post('/logout', protect, authController.logout);
router.get('/me', protect, authController.getMe);

// ──── ADMIN ONLY ROUTES ────
router.get('/all-users', protect, restrictTo('admin', 'superadmin'), authController.getAllUsers);

// ──── USER SELF-MANAGEMENT ────
router.patch('/update-me', protect, authController.updateMe);
router.delete('/delete-me', protect, authController.deleteMe);

// ──── ADMIN USER-MANAGEMENT ────
router.route('/all-users/:id')
  .patch(protect, restrictTo('admin', 'superadmin'), authController.updateUser)
  .get(protect, restrictTo('admin', 'superadmin'), authController.getUserById); // Cleaned up!

module.exports = router;