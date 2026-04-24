const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { protect, restrictTo, verifyGateway } = require('../middleware/auth');

router.use(verifyGateway);

router.post('/register', authController.register);
router.post('/login', authController.login);
router.post('/logout', protect, authController.logout);

// Usage tracking applied to billable routes
router.get('/me', protect, authController.trackUsage, authController.getMe);
router.get('/data', protect, authController.trackUsage, (req, res) => {
    res.json({ success: true, data: "Metered data delivered!" });
});
router.get('/usage', protect, authController.trackUsage, authController.getUsage);

router.get('/all-users', protect, restrictTo('admin', 'superadmin'), authController.getAllUsers);
router.patch('/update-me', protect, authController.updateMe);
router.delete('/delete-me', protect, authController.deleteMe);

router.route('/all-users/:id')
  .patch(protect, restrictTo('admin', 'superadmin'), authController.updateUser)
  .get(protect, restrictTo('admin', 'superadmin'), authController.getUserById);

module.exports = router;