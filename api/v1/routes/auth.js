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

// ──── USER SELF-MANAGEMENT ────
router.patch('/update-me', protect, authController.updateMe);
router.delete('/delete-me', protect, authController.deleteMe);

// ──── ADMIN USER-MANAGEMENT ────
router.route('/all-users/:id')
  .patch(protect, restrictTo('admin', 'superadmin'), authController.updateUser)
  .get(protect, restrictTo('admin', 'superadmin'), async (req, res) => {
      // Small helper to get one specific user by ID
      const user = await User.findById(req.params.id).select('-passwordHash');
      res.json({ success: true, user });
  });

module.exports = router;