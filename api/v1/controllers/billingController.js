/**
 * @file controllers/billingController.js
 * @description Stripe billing + early trial → credits switch.
 *
 * - createCheckoutSession: one-time credit pack purchase
 * - createPortalSession: Stripe customer portal
 * - addCredits: dev/admin credit injection
 * - switchToCredits: user ends trial early; remaining trial is added to credits
 */
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const User = require('../models/users');

/**
 * Create a Checkout Session to buy "Credit Packs" (Pay-as-you-go)
 */
exports.createCheckoutSession = async (req, res) => {
  try {
    const user = await User.findById(req.user.id || req.user._id);
    if (!user || !user.stripeCustomerId) {
      return res
        .status(400)
        .json({ success: false, error: 'User not linked to Stripe' });
    }

    const creditAmount = Number(req.body.credits) || 1000;
    const unitAmount = Number(req.body.amount) || Number(req.body.amountCents) || 1000;

    if (!Number.isInteger(creditAmount) || creditAmount <= 0) {
      return res.status(400).json({
        success: false,
        error: 'Invalid credit amount: must be a positive integer',
      });
    }

    if (!Number.isInteger(unitAmount) || unitAmount <= 0) {
      return res.status(400).json({
        success: false,
        error: 'Invalid unit amount in cents: must be a positive integer',
      });
    }

    const packName =
      req.body.name ||
      `API Credit Pack (${creditAmount.toLocaleString()} requests)`;

    const session = await stripe.checkout.sessions.create({
      customer: user.stripeCustomerId,
      payment_method_types: ['card'],
      mode: 'payment',
      line_items: [
        {
          price_data: {
            currency: 'usd',
            product_data: { name: packName },
            unit_amount: unitAmount,
          },
          quantity: 1,
        },
      ],
      metadata: {
        userId: user._id.toString(),
        credits: creditAmount.toString(),
      },
      success_url: `${process.env.CLIENT_URL}/billing?billing_success=true`,
      cancel_url: `${process.env.CLIENT_URL}/billing?billing_canceled=true`,
    });

    res.json({ success: true, url: session.url });
  } catch (err) {
    console.error('Billing Checkout Error:', err);
    if (
      err.type === 'StripeCardError' ||
      err.type === 'StripeInvalidRequestError'
    ) {
      return res.status(400).json({ success: false, error: err.message });
    }
    if (
      err.type === 'StripeConnectionError' ||
      err.type === 'StripeAPIError'
    ) {
      return res.status(503).json({
        success: false,
        error: 'Payment gateway temporarily unavailable. Please try again later.',
      });
    }
    res
      .status(500)
      .json({ success: false, error: 'Failed to create checkout session' });
  }
};

/**
 * Create a Portal Session
 */
exports.createPortalSession = async (req, res) => {
  try {
    const user = await User.findById(req.user.id || req.user._id);
    if (!user || !user.stripeCustomerId) {
      return res
        .status(400)
        .json({ success: false, error: 'User not linked to Stripe' });
    }

    const session = await stripe.billingPortal.sessions.create({
      customer: user.stripeCustomerId,
      return_url: `${process.env.CLIENT_URL}/billing`,
    });
    res.json({ success: true, url: session.url });
  } catch (err) {
    console.error('Portal Error:', err);
    if (err.type === 'StripeInvalidRequestError') {
      return res.status(400).json({ success: false, error: err.message });
    }
    res
      .status(500)
      .json({ success: false, error: 'Failed to create portal session' });
  }
};

/**
 * Admin/Dev endpoint to manually add credits
 */
exports.addCredits = async (req, res) => {
  try {
    if (process.env.NODE_ENV === 'production' && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Unauthorized' });
    }

    const creditDelta = Number(req.body.amount);
    if (!Number.isInteger(creditDelta) || creditDelta <= 0) {
      return res.status(400).json({
        success: false,
        error: 'Invalid credit amount: must be a positive integer',
      });
    }

    const user = await User.findByIdAndUpdate(
      req.user.id || req.user._id,
      { $inc: { credits: creditDelta } },
      { returnDocument: 'after' }
    ).select('-passwordHash');

    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    res.json({
      success: true,
      message: `Added ${creditDelta} credits`,
      credits: user.credits,
    });
  } catch (err) {
    console.error('Add Credits Error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
};

/**
 * Switch from trial to credit balance BEFORE trial ends.
 * - Sets isTrial = false
 * - Converts remaining trial requests into credits
 * - Idempotent: if already off trial, returns current state
 *
 * Can be called as Express handler or as pure function:
 *   const result = await switchToCredits(userId)
 */
async function switchToCredits(userId) {
  const user = await User.findById(userId);
  if (!user) {
    throw new Error('User not found');
  }

  if (!user.isTrial) {
    return {
      alreadySwitched: true,
      credits: user.credits || 0,
      isTrial: false,
      message: 'Already on credit balance',
    };
  }

  const trialLimit = user.trialLimit ?? 1000;
  const trialUsed = user.trialRequestsUsed ?? 0;
  const remaining = Math.max(0, trialLimit - trialUsed);

  const updated = await User.findByIdAndUpdate(
    userId,
    {
      isTrial: false,
      $inc: { credits: remaining },
      trialRequestsUsed: trialLimit,
    },
    { returnDocument: 'after' }
  ).select('-passwordHash');

  return {
    alreadySwitched: false,
    creditsAdded: remaining,
    credits: updated.credits,
    isTrial: false,
    message:
      remaining > 0
        ? `Trial ended. ${remaining.toLocaleString()} remaining trial requests were added to your credit balance.`
        : 'Trial ended. You are now on credit balance.',
  };
}

exports.switchToCredits = async (req, res) => {
  try {
    const userId = req.user.id || req.user._id;
    const result = await switchToCredits(userId);
    res.json({ success: true, ...result });
  } catch (err) {
    console.error('Switch to Credits Error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
};

// Pure function export for MCP / agentController reuse
exports.switchToCreditsFn = switchToCredits;
