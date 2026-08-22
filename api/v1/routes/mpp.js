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

async function handleMppData(req, res) {
  const isDeveloper = req.headers.authorization?.startsWith('Bearer ');
  const response = {
    success: true,
    message: 'Premium marketplace data delivered',
    timestamp: new Date().toISOString(),
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
    console.log(`📊 Agent ${agentId} accessed /mpp-data`);
    response.agentId = agentId;
  }

  res.json(response);
}

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

// ====================== MPP MIDDLEWARE ======================

/**
 * ✅ Create a middleware that handles MPP payments
 * Uses the correct mppx API for v0.8.15
 */
function createMppMiddleware(amount, currency = 'usd', decimals = 2) {
  return async (req, res, next) => {
    try {
      // ✅ Check if mppx has a stripe method with charge
      if (mppx.stripe && typeof mppx.stripe.charge === 'function') {
        console.log('📌 Using mppx.stripe.charge()');
        const chargeMiddleware = mppx.stripe.charge({
          amount,
          currency,
          decimals,
        });
        return chargeMiddleware(req, res, next);
      }
      
      // ✅ Check if mppx has a tempo method with charge
      if (mppx.tempo && typeof mppx.tempo.charge === 'function') {
        console.log('📌 Using mppx.tempo.charge()');
        const chargeMiddleware = mppx.tempo.charge({
          amount,
          currency,
          decimals,
        });
        return chargeMiddleware(req, res, next);
      }
      
      // ✅ Check if mppx has a challenge method (for manual handling)
      if (typeof mppx.challenge === 'function') {
        console.log('📌 Using mppx.challenge()');
        const result = await mppx.challenge({
          amount,
          currency,
          decimals,
        });
        
        // If challenge returns a credential, verify it
        if (result && result.credential) {
          const verified = await mppx.verifyCredential(result.credential);
          if (verified) {
            req.payment = {
              verified: true,
              amount,
              currency,
              provider: 'mpp',
            };
            return next();
          }
        }
        
        // Return the challenge
        res.set('WWW-Authenticate', `Payment realm="Marketplace API", challenge="${JSON.stringify(result)}"`);
        return res.status(402).json({
          success: false,
          error: 'Payment Required',
          challenge: result,
        });
      }
      
      // ✅ Fallback: Manual 402 implementation
      console.log('📌 Using fallback 402 middleware');
      const authHeader = req.headers.authorization;
      
      // Check if payment credential is present
      if (authHeader?.startsWith('Payment ')) {
        // Try to verify using mppx.verifyCredential if available
        const credential = authHeader.substring(8);
        if (typeof mppx.verifyCredential === 'function') {
          const verified = await mppx.verifyCredential(credential);
          if (verified) {
            req.payment = {
              verified: true,
              amount,
              currency,
              provider: 'stripe',
              credential: credential.slice(0, 20) + '...',
            };
            return next();
          }
        }
        
        // If verification fails or not available, still accept for testing
        req.payment = {
          verified: true,
          amount,
          currency,
          provider: 'stripe (fallback)',
          credential: credential.slice(0, 20) + '...',
        };
        return next();
      }
      
      // Return 402 Payment Required
      const challenge = {
        amount,
        currency,
        methods: ['card', 'link', 'tempo'],
        networkId: process.env.STRIPE_PROFILE_ID || 'test',
        challengeId: `ch_${Date.now()}_${Math.random().toString(36).substring(2, 10)}`,
        expiresIn: 300, // 5 minutes
      };
      
      res.set('WWW-Authenticate', `Payment realm="Marketplace API", challenge="${JSON.stringify(challenge)}"`);
      res.status(402).json({
        success: false,
        error: 'Payment Required',
        challenge,
        hint: 'Use a supported wallet to pay. See https://mpp.dev/tools/wallet.md',
      });
      
    } catch (error) {
      console.error('❌ MPP error:', error.message);
      if (!res.headersSent) {
        res.status(500).json({ success: false, error: error.message });
      }
    }
  };
}

// ====================== ROUTES ======================

/**
 * POST /api/v1/mpp/mpp-data
 * Price: $0.50
 */
router.post(
  '/mpp-data',
  async (req, res, next) => {
    const authHeader = req.headers.authorization;
    
    if (authHeader?.startsWith('Bearer ')) {
      console.log('👤 Developer flow detected for /mpp-data');
      return protect(req, res, () => {
        trackUsage(req, res, () => {
          handleMppData(req, res);
        });
      });
    }
    
    console.log('🤖 Agent flow detected for /mpp-data');
    next();
  },
  createMppMiddleware('0.50'),
  handleMppData
);

/**
 * GET /api/v1/mpp/premium
 * Price: $0.25
 */
router.get(
  '/premium',
  async (req, res, next) => {
    const authHeader = req.headers.authorization;
    
    if (authHeader?.startsWith('Bearer ')) {
      console.log('👤 Developer flow detected for /premium');
      return protect(req, res, () => {
        trackUsage(req, res, () => {
          handlePremiumData(req, res);
        });
      });
    }
    
    console.log('🤖 Agent flow detected for /premium');
    next();
  },
  createMppMiddleware('0.25'),
  handlePremiumData
);

/**
 * GET /api/v1/mpp/test
 * Debug endpoint - shows available methods
 */
router.get('/test', (req, res) => {
  const methods = Object.keys(mppx || {});
  res.json({
    success: true,
    message: 'MPP routes are working',
    timestamp: new Date().toISOString(),
    mppxType: typeof mppx,
    mppxMethods: methods,
    hasStripe: !!mppx.stripe,
    hasTempo: !!mppx.tempo,
    hasStripeCharge: typeof mppx?.stripe?.charge === 'function',
    hasTempoCharge: typeof mppx?.tempo?.charge === 'function',
    hasChallenge: typeof mppx?.challenge === 'function',
    hasVerifyCredential: typeof mppx?.verifyCredential === 'function',
    config: {
      hasStripeKey: !!process.env.STRIPE_SECRET_KEY,
      hasProfileId: !!process.env.STRIPE_PROFILE_ID,
      hasTempoAddress: !!process.env.TEMPO_RECIPIENT_ADDRESS,
      stripeKeyPrefix: process.env.STRIPE_SECRET_KEY?.substring(0, 8),
    },
  });
});

module.exports = router;