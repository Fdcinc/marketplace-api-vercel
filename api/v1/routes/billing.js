const express = require('express');
const router = express.Router();
const billingController = require('../controllers/billingController');
const { protect } = require('../middleware/authMiddleware'); // Assuming you have a protect middleware

router.post('/create-checkout-session', protect, billingController.createCheckoutSession);
router.post('/create-portal-session', protect, billingController.createPortalSession);
router.post('/add-credits', protect, billingController.addCredits);

module.exports = router;