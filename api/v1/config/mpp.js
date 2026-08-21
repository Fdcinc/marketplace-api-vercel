/**
 * @file v1/config/mpp.js
 * @description Centralized Machine Payments Protocol (MPP) initialization via Stripe.
 */
// ====================== MPP SETUP ======================

const Stripe = require('stripe');
const { Mppx, stripe: mppStripe } = require('mppx/express');

const stripeClient = new Stripe(process.env.STRIPE_SECRET_KEY, {
  apiVersion: '2026-03-25.preview',
});

const mppx = Mppx.create({
  secretKey: process.env.MPP_SECRET_KEY || process.env.STRIPE_SECRET_KEY,
  methods: [
    mppStripe.charge({
      client: stripeClient,
      networkId: process.env.STRIPE_PROFILE_ID,
      paymentMethodTypes: ['card', 'link'],
      decimals: 2,
    }),
  ],
});

module.exports = { mppx };