/**
 * @file services/stripeService.js
 * @description Stripe customer synchronization helpers.
 * Assumes MongoDB is already connected globally.
 */
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

exports.ensureStripeCustomer = async (user) => {
  if (user.stripeCustomerId) return user.stripeCustomerId;

  try {
    console.log(`👤 Syncing Stripe Customer for ${user.email}...`);
    const customer = await stripe.customers.create({
      email: user.email,
      name: user.name || 'User',
      metadata: { source: 'marketplace_api_sync' },
    });

    user.stripeCustomerId = customer.id;
    await user.save();
    console.log(`✅ Stripe Customer ${customer.id} synced to ${user.email}`);
    return customer.id;
  } catch (err) {
    console.error(`❌ Stripe Sync Error for ${user.email}:`, err.message);
    throw err;
  }
};