/**
 * @file routes/agent.js
 * @description Agent/Billing Assistant routes.
 * POST /api/v1/agent/chat - Chat with billing AI (billed).
 *
 * @middleware protect, trackUsage
 */
const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/authMiddleware');
const trackUsage = require('../middleware/trackUsage'); // ✅ new location
const agentController = require('../controllers/agentController');

// This route costs 1 credit every time they ask the AI a question
router.post('/chat', protect, trackUsage, agentController.billingAssistant);

/*
// Get usage summary for the current user
router.get('/usage-summary', protect, async (req, res) => {
  try {
    const stats = await agentController.getUsageSummaryForPrompt(req.user.id);
    res.json({ success: true, data: stats });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Billing summary (existing)
router.get('/billing-summary', protect, agentController.getBillingSummary);

// MPP analytics (existing)
router.get('/mpp-analytics', protect, agentController.getMppAnalytics);

// Credit packs (existing)
router.get('/credit-packs', protect, agentController.getCreditPacks);

 */

module.exports = router;