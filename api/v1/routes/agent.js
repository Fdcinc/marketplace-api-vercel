// routes/agent.js
/**
 * @file routes/agent.js
 * @description Agent/Billing Assistant routes.
 * POST /api/v1/agent/chat - Chat with billing AI (billed).
 * 
 * @middleware protect, trackUsage (via controller)
 */
const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/authMiddleware');
const { trackUsage } = require('../controllers/authController');
const agentController = require('../controllers/agentController');

// This route costs 1 credit every time they ask the AI a question
router.post('/chat', protect, trackUsage, agentController.billingAssistant);

module.exports = router;