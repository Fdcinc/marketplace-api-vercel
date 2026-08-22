/**
 * @file v1/routes/mpp.js
 * @description Machine Payments Protocol (MPP) paid routes
 */

const express = require('express');
const router = express.Router();
const { mppx } = require('../config/mpp');
const { protect } = require('../middleware/authMiddleware');
const trackUsage = require('../middleware/trackUsage');

// ====================== HANDLERS ======================

/**
 * Handler for /mpp-data endpoint
 * Used by both developers (after credits check) and agents (after MPP payment)
 */
async function handleMppData(req, res) {
  const isDeveloper = req.headers.authorization?.startsWith('Bearer ');
  const response = {
    success: true,
    message: 'Premium marketplace data delivered',
    timestamp: new Date().toISOString(),
  };

  if (isDeveloper) {
    // Developer paid with credits
    response.paidBy = 'developer (credits)';
    response.creditsRemaining = req.user?.credits || 0;
  } else {
    // Agent paid via MPP
    response.paidBy = 'agent (MPP)';
    response.paymentDetails = req.payment || {};
  }

  // Track agent usage
  const agentId = req.headers['x-agent-id'];
  if (agentId) {
    console.log(`📊 Agent ${agentId} accessed /mpp-data`);
    response.agentId = agentId;
  }

  res.json(response);
}

/**
 * Handler for /premium endpoint
 * Used by both developers (after credits check) and agents (after MPP payment)
 */
async function handlePremiumData(req, res) {
  const isDeveloper = req.headers.authorization?.startsWith('Bearer ');
  const response = {
    success: true,
    message: 'Premium insights delivered',
    data: {
      insight: 'High-value marketplace insight',
      timestamp: new Date().toISOString(),
    },
  };

  if (isDeveloper) {
    response.paidBy = 'developer (credits)';
    response.creditsRemaining = req.user?.credits || 0;
  } else {
    response.paidBy = 'agent (MPP)';
    response.paymentDetails = req.payment || {};
  }

  const agentId = req.headers['x-agent-id'];
  if (agentId) {
    console.log(`📊 Agent ${agentId} accessed /premium`);
    response.agentId = agentId;
  }

  res.json(response);
}

// ====================== ROUTES ======================

/**
 * POST /api/v1/mpp/mpp-data
 * Price: $0.50
 * 
 * WORKS FOR BOTH:
 * - Developers: Use API key + credits (via protect + trackUsage)
 * - Agents: Pay via MPP (no API key needed)
 */
router.post(
  '/mpp-data',
  // ✅ Step 1: Dual-path middleware
  async (req, res, next) => {
    const authHeader = req.headers.authorization;
    
    // Developer flow: has Bearer token
    if (authHeader?.startsWith('Bearer ')) {
      console.log('👤 Developer flow detected for /mpp-data');
      // ✅ CRITICAL: Pass control to protect, then trackUsage, then final handler
      return protect(req, res, () => {
        trackUsage(req, res, () => {
          // Skip MPP middleware and go directly to final handler
          handleMppData(req, res);
        });
      });
    }
    
    // Agent flow: no auth header, proceed to MPP payment
    console.log('🤖 Agent flow detected for /mpp-data');
    next();
  },
  // ✅ Step 2: Agent payment middleware (MPP) - ONLY for agent requests
  mppx.charge({
    amount: '0.50',
    currency: 'usd',
    decimals: 2,
  }),
  // ✅ Step 3: Final handler - for successful agent payments
  handleMppData
);

/**
 * GET /api/v1/mpp/premium
 * Price: $0.25
 * 
 * WORKS FOR BOTH:
 * - Developers: Use API key + credits
 * - Agents: Pay via MPP
 */
router.get(
  '/premium',
  // ✅ Step 1: Dual-path middleware
  async (req, res, next) => {
    const authHeader = req.headers.authorization;
    
    // Developer flow
    if (authHeader?.startsWith('Bearer ')) {
      console.log('👤 Developer flow detected for /premium');
      return protect(req, res, () => {
        trackUsage(req, res, () => {
          handlePremiumData(req, res);
        });
      });
    }
    
    // Agent flow
    console.log('🤖 Agent flow detected for /premium');
    next();
  },
  // ✅ Step 2: Agent payment middleware (MPP)
  mppx.charge({
    amount: '0.25',
    currency: 'usd',
    decimals: 2,
  }),
  // ✅ Step 3: Final handler
  handlePremiumData
);

/**
 * GET /api/v1/mpp/test
 * @description Test endpoint to verify MPP configuration
 */
router.get('/test', (req, res) => {
  res.json({
    success: true,
    message: 'MPP routes are working',
    timestamp: new Date().toISOString(),
    config: {
      hasStripeKey: !!process.env.STRIPE_SECRET_KEY,
      hasProfileId: !!process.env.STRIPE_PROFILE_ID,
      mppxMethods: mppx.methods ? mppx.methods.length : 0,
    },
    endpoints: {
      mppData: 'POST /api/v1/mpp/mpp-data ($0.50)',
      premium: 'GET /api/v1/mpp/premium ($0.25)',
    },
  });
});

module.exports = router;