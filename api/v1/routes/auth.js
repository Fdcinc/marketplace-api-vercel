const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { protect, restrictTo } = require('../middleware/auth');

// ──── PUBLIC ROUTES ────
router.post('/register', authController.register);
router.post('/login', authController.login);

// ──── PROTECTED ROUTES ────
router.post('/logout', protect, authController.logout);
router.get('/me', protect, authController.getMe);

// ──── ADMIN ONLY ROUTES ────
// Fixed: Changed userController to authController
router.get('/all-users', protect, restrictTo('admin', 'superadmin'), authController.getAllUsers);

module.exports = router;