/**
 * @file controllers/webhookController.js
 * @description Stripe webhook handlers with event-id idempotency.
 */
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const User = require('../models/users');
const ProcessedStripeEvent = require('../models/processedStripeEvent');

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

  console.log(`🔔 Webhook received: ${event.type} (${event.id})`);

  const objectId = event.data?.object?.id || null;
  try {
    await ProcessedStripeEvent.create({
      eventId: event.id,
      type: event.type,
      objectId,
    });
  } catch (err) {
    if (err && err.code === 11000) {
      console.log(`♻️ Duplicate event ignored: ${event.id} (${event.type})`);
      return res.json({ received: true, duplicate: true });
    }
    console.error('❌ Failed to record webhook event id:', err.message);
    return res.status(500).json({ received: false, error: 'Idempotency store failed' });
  }

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
  }

  res.json({ received: true });
};

async function handleMeterSummaryUpdated(summary) {
  const customerId = summary.customer;
  if (!customerId) {
    console.warn('⚠️ meter summary missing customer');
    return;
  }

  const updatedUser = await User.findOneAndUpdate(
    { stripeCustomerId: customerId },
    {
      currentUsage: summary.aggregate_value ?? summary.aggregated_value,
      usageLastUpdated: new Date(),
    },
    { returnDocument: 'after' }
  );

  if (updatedUser) {
    console.log(`✅ MongoDB Synced Usage: ${updatedUser.email}`);
  }
}

async function handleCheckoutSessionCompleted(session) {
  if (!session.customer) {
    console.warn('⚠️ checkout.session.completed missing customer — skip credits');
    return;
  }

  if (session.mode && session.mode !== 'payment') {
    console.log(`ℹ️ Skipping credits for checkout mode=${session.mode}`);
    return;
  }

  const creditsToAdd = Number(session.metadata?.credits) || 1000;
  if (!Number.isFinite(creditsToAdd) || creditsToAdd <= 0) {
    console.warn('⚠️ Invalid credits metadata — skip');
    return;
  }

  const updatedUser = await User.findOneAndUpdate(
    { stripeCustomerId: session.customer },
    { $inc: { credits: creditsToAdd } },
    { returnDocument: 'after' }
  );

  if (updatedUser) {
    console.log(
      `💰 Credits (+${creditsToAdd}) added to ${updatedUser.email}. New balance: ${updatedUser.credits}`
    );
  } else {
    console.warn(
      `⚠️ No user found for stripeCustomerId=${session.customer} (session ${session.id})`
    );
  }
}