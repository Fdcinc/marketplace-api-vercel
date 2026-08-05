/**
 * @file middleware/trackUsage.js
 * @description Metering middleware: trial quota → credits → 402.
 * Assumes MongoDB is already connected and protect has set req.user.
 *
 * Usage:
 *   router.post('/chat', protect, trackUsage, controller.handler);
 */
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const User = require('../models/users');

/** Routes that never consume trial/credits */
const FREE_ROUTES = new Set(['/api/v1/auth/me', '/api/v1/auth/usage']);

/**
 * trackUsage middleware
 * 1. Skip free routes
 * 2. Trial path: increment trialRequestsUsed while under limit
 * 3. Paid path: block if credits <= 0, else decrement credits + report to Stripe
 */
async function trackUsage(req, res, next) {
  console.log('DEBUG: trackUsage middleware running for route', req.originalUrl);

  try {
    if (FREE_ROUTES.has(req.originalUrl)) return next();
    if (!req.user) return next();

    const userId = req.user.id || req.user._id;
    const user = await User.findById(userId);
    if (!user) return next();

    // ── Trial path ──────────────────────────────────────────
    if (user.isTrial) {
      if (user.trialRequestsUsed < user.trialLimit) {
        await User.findByIdAndUpdate(user._id, {
          $inc: { trialRequestsUsed: 1 },
        });
        console.log(
          `✅ Trial usage for ${user.email}: ${user.trialRequestsUsed + 1}/${user.trialLimit}`
        );
        return next();
      }
      // Trial exhausted → move to paid path
      await User.findByIdAndUpdate(user._id, { isTrial: false });
    }

    // ── Paid guardrail ──────────────────────────────────────
    if ((user.credits || 0) <= 0) {
      console.log(`🚫 Blocked: ${user.email} has no credits.`);
      return res.status(402).json({
        success: false,
        error: 'Insufficient credits. Please top up.',
      });
    }

    // ── Stripe meter event (fire-and-forget) ────────────────
    if (user.stripeCustomerId) {
      stripe.billing.meterEvents
        .create({
          event_name: 'api_request',
          payload: {
            stripe_customer_id: user.stripeCustomerId,
            value: '1',
          },
        })
        .catch((e) => console.error('❌ Stripe Ingestion Error:', e.message));
    }

    // ── Local credit / usage decrement ──────────────────────
    await User.findByIdAndUpdate(user._id, {
      $inc: { credits: -1, currentUsage: 1 },
    });

    next();
  } catch (err) {
    console.error('❌ TrackUsage Error:', err.message);
    // Fail open so a metering bug does not take the API offline
    next();
  }
}

module.exports = trackUsage;
module.exports.trackUsage = trackUsage;
