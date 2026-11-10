/**
 * @file middleware/paidRoute.js
 * @description Dual-auth paid route helper.
 * - Bearer token → developer credit / trial flow (protect + trackUsage)
 * - Otherwise → MPP charge (card / Link / Tempo)
 */
const { mppx } = require('../config/mpp');
const { protect } = require('./authMiddleware');
const trackUsage = require('./trackUsage');

/**
 * @param {string|number} amount - Amount in major units (e.g. "0.50")
 * @returns {import('express').RequestHandler[]}
 */
function paidRoute(amount) {
  return [
    // 1. Developer Flow: Check for JWT
    (req, res, next) => {
      const authHeader = req.headers.authorization || '';
      if (authHeader.startsWith('Bearer ')) {
        return protect(req, res, (err) => {
          if (err) return next(err);
          return trackUsage(req, res, next);
        });
      }
      next(); // Not a developer, proceed to Agent flow
    },

    // 2. Agent Flow: MPP Charge
    (req, res, next) => {
      // If protect() succeeded, req.user exists. Bypass MPP.
      if (req.user) return next(); 
      
      // ✅ DO NOT pass `currency` here. 
      // Let config/mpp.js automatically compose the Stripe (usd) and Tempo (pathUSD) challenges.
      return mppx.charge({ amount: String(amount) })(req, res, next);
    },
  ];
}

module.exports = { paidRoute };