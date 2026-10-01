/**
 * @file middleware/trackUsage.js
 * @description Metering middleware: trial quota → credits → 402.
 * Atomic version using aggregation pipeline.
 * Assumes MongoDB is already connected and protect has set req.user.
 */
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const User = require('../models/users');

const FREE_ROUTES = new Set(['/api/v1/auth/me', '/api/v1/auth/usage']);

async function trackUsage(req, res, next) {
  if (FREE_ROUTES.has(req.originalUrl) || !req.user) return next();

  const userId = req.user.id || req.user._id;

  try {
    // Atomic update with aggregation pipeline
    const updated = await User.findOneAndUpdate(
      { _id: userId },                     // simple filter
      [
        {
          $set: {
            // 1. Increment trial counter only while still on trial and under limit
            trialRequestsUsed: {
              $cond: [
                {
                  $and: [
                    { $eq: ['$isTrial', true] },
                    { $lt: ['$trialRequestsUsed', '$trialLimit'] },
                  ],
                },
                { $add: ['$trialRequestsUsed', 1] },
                '$trialRequestsUsed',
              ],
            },

            // 2. Turn trial off when the limit is reached
            isTrial: {
              $cond: [
                {
                  $and: [
                    { $eq: ['$isTrial', true] },
                    { $gte: [{ $add: ['$trialRequestsUsed', 1] }, '$trialLimit'] },
                  ],
                },
                false,
                '$isTrial',
              ],
            },

            // 3. Decrement credits only when NOT on trial
            credits: {
              $cond: [
                { $eq: ['$isTrial', true] },
                '$credits',
                { $max: [0, { $subtract: ['$credits', 1] }] },
              ],
            },

            currentUsage: { $add: ['$currentUsage', 1] },
            usageLastUpdated: new Date(),
          },
        },
      ],
      {
        returnDocument: 'after',
        updatePipeline: true,          // ← required when update is an array
      }
    );

    if (!updated) {
      return res.status(402).json({
        success: false,
        error: 'User not found or insufficient credits / trial exhausted.',
      });
    }

    // Extra safety check after the update
    if (!updated.isTrial && (updated.credits || 0) <= 0) {
      return res.status(402).json({
        success: false,
        error: 'Insufficient credits. Please top up.',
      });
    }

    // Fire-and-forget Stripe meter event
    if (updated.stripeCustomerId) {
      stripe.billing.meterEvents
        .create({
          event_name: 'api_request',
          payload: {
            stripe_customer_id: updated.stripeCustomerId,
            value: '1',
          },
        })
        .catch((e) => console.error('❌ Stripe meter error:', e.message));
    }

    // Attach useful info for controllers
    req.creditsRemaining = updated.credits;
    req.isTrial = updated.isTrial;

    next();
  } catch (err) {
    console.error('❌ TrackUsage Error:', err.message);
    next(); // fail open
  }
}

module.exports = trackUsage;
module.exports.trackUsage = trackUsage;