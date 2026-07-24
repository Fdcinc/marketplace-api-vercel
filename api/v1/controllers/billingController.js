/**
 * @file controllers/billingController.js
 * @description Stripe billing operations with input validation and specific error handling.
 * 
 * - createCheckoutSession: One-time credit pack purchase with explicit credit metadata & validation
 * - createPortalSession: Customer billing portal session
 * - addCredits: Dev/Admin credit injection with strict validation
 */
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const User = require('../models/users');

// 1. Create a Checkout Session to buy "Credit Packs" (Pay-as-you-go)
exports.createCheckoutSession = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user || !user.stripeCustomerId) {
      return res.status(400).json({ success: false, error: "User not linked to Stripe" });
    }

    // Input validation & sanitization
    const creditAmount = Number(req.body.credits);
    const unitAmount = Number(req.body.amount);

    if (!Number.isInteger(creditAmount) || creditAmount <= 0) {
      return res.status(400).json({ success: false, error: "Invalid credit amount: must be a positive integer" });
    }

    if (!Number.isInteger(unitAmount) || unitAmount <= 0) {
      return res.status(400).json({ success: false, error: "Invalid unit amount in cents: must be a positive integer" });
    }

    const packName = req.body.name || `API Credit Pack (${creditAmount.toLocaleString()} requests)`;

    const session = await stripe.checkout.sessions.create({
      customer: user.stripeCustomerId,
      payment_method_types: ['card'],
      mode: 'payment', // One-time payment
      line_items: [{
        price_data: {
          currency: 'usd',
          product_data: { name: packName },
          unit_amount: unitAmount,
        },
        quantity: 1,
      }],
      metadata: {
        userId: user._id.toString(),
        credits: creditAmount.toString(),
      },
      success_url: `${process.env.CLIENT_URL}/dashboard?billing_success=true`,
      cancel_url: `${process.env.CLIENT_URL}/dashboard?billing_canceled=true`,
    });

    res.json({ success: true, url: session.url });
  } catch (err) {
    console.error("Billing Checkout Error:", err);
    
    // Handle specific Stripe API errors
    if (err.type === 'StripeCardError' || err.type === 'StripeInvalidRequestError') {
      return res.status(400).json({ success: false, error: err.message });
    }
    if (err.type === 'StripeConnectionError' || err.type === 'StripeAPIError') {
      return res.status(503).json({ success: false, error: "Payment gateway temporarily unavailable. Please try again later." });
    }

    res.status(500).json({ success: false, error: "Failed to create checkout session" });
  }
};

// 2. Create a Portal Session to let users manage cards/invoices
exports.createPortalSession = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user || !user.stripeCustomerId) {
      return res.status(400).json({ success: false, error: "User not linked to Stripe" });
    }

    const session = await stripe.billingPortal.sessions.create({
      customer: user.stripeCustomerId,
      return_url: `${process.env.CLIENT_URL}/dashboard`,
    });
    res.json({ success: true, url: session.url });
  } catch (err) {
    console.error("Portal Error:", err);

    if (err.type === 'StripeInvalidRequestError') {
      return res.status(400).json({ success: false, error: err.message });
    }

    res.status(500).json({ success: false, error: "Failed to create portal session" });
  }
};

// 3. Admin/Dev endpoint to manually add credits
exports.addCredits = async (req, res) => {
  try {
    // SECURITY: Only allow this in development or if user is admin
    if (process.env.NODE_ENV === 'production' && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, error: "Unauthorized" });
    }

    const { amount } = req.body;
    const creditDelta = Number(amount);

    if (!Number.isInteger(creditDelta) || creditDelta <= 0) {
      return res.status(400).json({ success: false, error: "Invalid credit amount: must be a positive integer" });
    }

    const user = await User.findByIdAndUpdate(
      req.user.id, 
      { $inc: { credits: creditDelta } }, 
      { returnDocument: 'after' }
    ).select('-passwordHash');

    if (!user) {
      return res.status(404).json({ success: false, error: "User not found" });
    }

    res.json({ success: true, message: `Added ${creditDelta} credits`, credits: user.credits });
  } catch (err) {
    console.error("Add Credits Error:", err);
    res.status(500).json({ success: false, error: err.message });
  }
};