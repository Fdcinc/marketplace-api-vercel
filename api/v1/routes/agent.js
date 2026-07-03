// routes/agent.js
const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/authMiddleware');
const { trackUsage } = require('../controllers/authController');
const agentController = require('../controllers/agentController');

// This route costs 1 credit every time they ask the AI a question
router.post('/chat', protect, agentController.billingAssistant);

module.exports = router;