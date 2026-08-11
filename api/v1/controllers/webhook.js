/**
 * @file controllers/webhookController.js
 * @description Stripe webhook handlers with signature verification + event-id idempotency.
 *
 * CRITICAL: This route MUST receive the raw request body (Buffer), not parsed JSON.
 * Register BEFORE express.json():
 *   app.post('/api/v1/webhooks', express.raw({ type: 'application/json' }), handleStripeWebhook)
 *
 * Env:
 *   STRIPE_SECRET_KEY
 *   STRIPE_WEBHOOK_SECRET  — Dashboard endpoint secret, or CLI `whsec_` while using `stripe listen`
 */
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const User = require('../models/users');
const ProcessedStripeEvent = require('../models/processedStripeEvent');

/**
 * Verify Stripe-Signature and parse the event.
 * @returns {{ ok: true, event: import('stripe').Stripe.Event } | { ok: false, status: number, message: string }}
 */
function verifyStripeSignature(req) {
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!webhookSecret) {
    return {
      ok: false,
      status: 500,
      message: 'Server misconfigured: STRIPE_WEBHOOK_SECRET is not set',
    };
  }

  const signature = req.headers['stripe-signature'];
  if (!signature) {
    return {
      ok: false,
      status: 400,
      message: 'Missing Stripe-Signature header',
    };
  }

  // express.raw() provides a Buffer; constructEvent requires the exact bytes Stripe signed
  const payload = req.body;
  if (!Buffer.isBuffer(payload) && typeof payload !== 'string') {
    return {
      ok: false,
      status: 400,
      message:
        'Invalid body type for webhook verification (expected raw Buffer). ' +
        'Ensure express.raw() is used and runs before express.json().',
    };
  }

  try {
    const event = stripe.webhooks.constructEvent(
      payload,
      signature,
      webhookSecret
    );
    return { ok: true, event };
  } catch (err) {
    return {
      ok: false,
      status: 400,
      message: err.message || 'Webhook signature verification failed',
    };
  }
}

/**
 * Main Stripe webhook entry point.
 * 1) Verify signature
 * 2) Claim event.id (idempotency)
 * 3) Handle checkout.session.completed / meter summary
 */
exports.handleStripeWebhook = async (req, res) => {
  const verified = verifyStripeSignature(req);
  if (!verified.ok) {
    console.error(`⚠️ Webhook signature verification failed: ${verified.message}`);
    return res.status(verified.status).send(`Webhook Error: ${verified.message}`);
  }

  const { event } = verified;
  console.log(`🔔 Webhook received: ${event.type} (${event.id})`);

  // ── Idempotency claim ────────────────────────────────────────────────
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
    return res
      .status(500)
      .json({ received: false, error: 'Idempotency store failed' });
  }

  // ── Process once ─────────────────────────────────────────────────────
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

// Exported for unit tests
exports.verifyStripeSignature = verifyStripeSignature;
