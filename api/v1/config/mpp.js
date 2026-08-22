/**
 * @file v1/config/mpp.js
 * @description Centralized Machine Payments Protocol (MPP) initialization via Stripe + Tempo.
 */

const Stripe = require('stripe');
const { Mppx, stripe: mppStripe, tempo } = require('mppx/express');

const stripeClient = new Stripe(process.env.STRIPE_SECRET_KEY, {
  apiVersion: '2026-03-25.preview',
});

// ✅ Create the MPPX instance
const mppx = Mppx.create({
  secretKey: process.env.MPP_SECRET_KEY || process.env.STRIPE_SECRET_KEY,
  methods: [
    mppStripe.charge({
      client: stripeClient,
      networkId: process.env.STRIPE_PROFILE_ID,
      paymentMethodTypes: ['card', 'link'],
      decimals: 2,
    }),
    tempo.charge({
      currency: '0x20c0000000000000000000000000000000000000', // pathUSD on Tempo
      recipient: process.env.TEMPO_RECIPIENT_ADDRESS,
      testnet: process.env.NODE_ENV !== 'production',
    }),
  ],
});

// ✅ Log what methods are available on mppx
console.log('🔍 mppx methods:', Object.keys(mppx || {}));

module.exports = { mppx, stripeClient };