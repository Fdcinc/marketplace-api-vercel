/**
 * @file controllers/webhookController.js
 * @description Stripe webhook handlers (metering + credit pack purchases).
 * Assumes MongoDB is already connected globally at app startup.
 *
 * Register with raw body BEFORE express.json():
 *   app.post('/api/v1/webhooks', express.raw({ type: 'application/json' }), handleStripeWebhook)
 */
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const User = require('../models/users');

/**
 * Main Stripe webhook entry point.
 * Handles:
 *  - billing.meter.summary_updated  → sync currentUsage
 *  - checkout.session.completed     → add credits from metadata
 */
exports.handleStripeWebhook = async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    console.error(`⚠️ Webhook signature verification failed: ${err.message}`);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  console.log(`🔔 Webhook received: ${event.type}`);

  try {
    switch (event.type) {
      case 'billing.meter.summary_updated':
        await handleMeterSummaryUpdated(event.data.object);
        break;

      case 'checkout.session.completed':
        await handleCheckoutSessionCompleted(event.data.object);
        break;

      default:
        console.log(`ℹ️ Unhandled event type: ${event.type}`);
    }
  } catch (err) {
    console.error('❌ Webhook processing error:', err.message);
    // Still return 200 so Stripe does not retry endlessly on our logic bugs
  }

  res.json({ received: true });
};

async function handleMeterSummaryUpdated(summary) {
  const updatedUser = await User.findOneAndUpdate(
    { stripeCustomerId: summary.customer },
    {
      currentUsage: summary.aggregate_value,
      usageLastUpdated: new Date(),
    },
    { returnDocument: 'after' }
  );

  if (updatedUser) {
    console.log(`✅ MongoDB Synced Usage: ${updatedUser.email}`);
  }
}

async function handleCheckoutSessionCompleted(session) {
  const creditsToAdd = Number(session.metadata?.credits) || 1000;

  const updatedUser = await User.findOneAndUpdate(
    { stripeCustomerId: session.customer },
    { $inc: { credits: creditsToAdd } },
    { returnDocument: 'after' }
  );

  if (updatedUser) {
    console.log(
      `💰 Credits (+${creditsToAdd}) added to ${updatedUser.email}. New balance: ${updatedUser.credits}`
    );
  }
}
