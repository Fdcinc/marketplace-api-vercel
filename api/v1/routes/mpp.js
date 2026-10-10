/**
 * @file v1/routes/mpp.js
 * @description Machine Payments Protocol (MPP) paid routes
 * Dual flow: Bearer → developer credits | otherwise → Tempo + Stripe 402
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
    response.paymentDetails = req.payment || req.mpp || {};
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
    response.paymentDetails = req.payment || req.mpp || {};
  }

  const agentId = req.headers['x-agent-id'];
  if (agentId) {
    console.log(`📊 Agent ${agentId} accessed /premium`);
    response.agentId = agentId;
  }

  res.json(response);
}

// ====================== DEVELOPER vs AGENT GATE ======================

function developerOrAgent(handler) {
  return (req, res, next) => {
    const authHeader = req.headers.authorization || '';

    if (authHeader.startsWith('Bearer ')) {
      console.log('👤 Developer flow:', req.path);
      return protect(req, res, () => {
        trackUsage(req, res, () => handler(req, res));
      });
    }

    console.log('🤖 Agent flow:', req.path);
    next(); // continue to mppx.charge middleware
  };
}

// ====================== OFFICIAL CHARGE MIDDLEWARE ======================
// mppx.charge() composes EVERY registered method (Stripe + Tempo)
// into one 402 Challenge. This is the correct API.

function mppCharge(amount) {
  if (typeof mppx?.charge === 'function') {
    console.log('📌 Using mppx.charge() – Stripe + Tempo');
    return mppx.charge({ amount: String(amount) });
  }

  // Fallbacks (should rarely be needed)
  if (mppx?.tempo && typeof mppx.tempo.charge === 'function') {
    console.log('📌 Fallback: mppx.tempo.charge()');
    return mppx.tempo.charge({ amount: String(amount) });
  }
  if (mppx?.stripe && typeof mppx.stripe.charge === 'function') {
    console.log('📌 Fallback: mppx.stripe.charge()');
    return mppx.stripe.charge({ amount: String(amount) });
  }

  // Last resort manual 402
  return (req, res) => {
    res.status(402).json({
      success: false,
      error: 'Payment Required',
      hint: 'No payment method registered on mppx',
    });
  };
}

// ====================== ROUTES ======================

router.post(
  '/mpp-data',
  developerOrAgent(handleMppData),
  mppCharge('0.50'),
  handleMppData
);

router.get(
  '/premium',
  developerOrAgent(handlePremiumData),
  mppCharge('0.25'),
  handlePremiumData
);

router.get('/test', (req, res) => {
  const methods = Object.keys(mppx || {});
  res.json({
    success: true,
    message: 'MPP routes are working',
    timestamp: new Date().toISOString(),
    mppxType: typeof mppx,
    mppxMethods: methods,
    hasCharge: typeof mppx?.charge === 'function',
    hasStripe: !!mppx.stripe,
    hasTempo: !!mppx.tempo,
    hasStripeCharge: typeof mppx?.stripe?.charge === 'function',
    hasTempoCharge: typeof mppx?.tempo?.charge === 'function',
    config: {
      hasStripeKey: !!process.env.STRIPE_SECRET_KEY,
      hasProfileId: !!process.env.STRIPE_PROFILE_ID,
      hasTempoAddress: !!process.env.TEMPO_RECIPIENT_ADDRESS,
      hasMppSecret: !!(process.env.MPP_SECRET_KEY || process.env.STRIPE_SECRET_KEY),
      stripeKeyPrefix: process.env.STRIPE_SECRET_KEY?.substring(0, 8),
    },
  });
});

module.exports = router;