const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { protect, restrictTo, verifyGateway } = require('../middleware/auth'); // Added verifyGateway

// 🔒 GATEWAY PROTECTION
// This applies to ALL routes below. If the request doesn't come from Kong, it stops here.
router.use(verifyGateway);

// ──── PUBLIC ROUTES ────
// (Still public to users, but "private" to the internet because they must pass through Kong)
router.post('/register', authController.register);
router.post('/login', authController.login);

// ──── PROTECTED ROUTES (Requires Gateway + JWT)
router.post('/logout', protect, authController.logout);
router.get('/me', protect, authController.getMe);

// ──── ADMIN ONLY ROUTES
router.get('/all-users', protect, restrictTo('admin', 'superadmin'), authController.getAllUsers);

// ──── USER SELF-MANAGEMENT ────
router.patch('/update-me', protect, authController.updateMe);
router.delete('/delete-me', protect, authController.deleteMe);

// ──── ADMIN USER-MANAGEMENT ────
router.route('/all-users/:id')
  .patch(protect, restrictTo('admin', 'superadmin'), authController.updateUser)
  .get(protect, restrictTo('admin', 'superadmin'), async (req, res) => {
      const user = await User.findById(req.params.id).select('-passwordHash');
      res.json({ success: true, user });
  });

module.exports = router;