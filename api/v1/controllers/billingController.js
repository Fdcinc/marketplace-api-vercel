const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const User = require('../models/users');

// 1. Create a Checkout Session to buy "Credit Packs" (Pay-as-you-go)
exports.createCheckoutSession = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user || !user.stripeCustomerId) {
      return res.status(400).json({ success: false, error: "User not linked to Stripe" });
    }

    const session = await stripe.checkout.sessions.create({
      customer: user.stripeCustomerId,
      payment_method_types: ['card'],
      mode: 'payment', // One-time payment
      line_items: [{
        price_data: {
          currency: 'usd',
          product_data: { name: 'API Credit Pack (1,000 requests)' },
          unit_amount: 1000, // $10.00
        },
        quantity: 1,
      }],
      success_url: `${process.env.CLIENT_URL}/dashboard?billing_success=true`,
      cancel_url: `${process.env.CLIENT_URL}/dashboard?billing_canceled=true`,
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error("Billing Checkout Error:", err);
    res.status(500).json({ success: false, error: "Failed to create checkout session" });
  }
};

// 2. Create a Portal Session to let users manage cards/invoices
exports.createPortalSession = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    const session = await stripe.billingPortal.sessions.create({
      customer: user.stripeCustomerId,
      return_url: `${process.env.CLIENT_URL}/dashboard`,
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error("Portal Error:", err);
    res.status(500).json({ success: false, error: "Failed to create portal session" });
  }
};

// controllers/billingController.js

exports.addCredits = async (req, res) => {
  try {
    // SECURITY: Only allow this in development or if user is admin
    if (process.env.NODE_ENV === 'production' && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, error: "Unauthorized" });
    }

    const { amount } = req.body;
    const user = await User.findByIdAndUpdate(
      req.user.id, 
      { $inc: { credits: amount || 1000 } }, 
      { returnDocument: 'after' }
    );

    res.json({ success: true, message: `Added ${amount || 1000} credits`, credits: user.credits });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};