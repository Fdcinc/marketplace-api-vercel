/**
 * @file v1/config/mpp.js
 * @description Centralized Machine Payments Protocol (MPP) initialization
 *              via Stripe (cards/link) + Tempo (pathUSD).
 *
 * - Stripe SPT: card + Link
 * - Tempo charge: pathUSD on Moderato testnet (dev) or mainnet (production)
 *
 * Official docs:
 *   - https://mpp.dev/sdk/typescript/middlewares/express
 *   - https://mpp.dev/payment-methods/tempo/charge
 *   - https://docs.tempo.xyz/guide/machine-payments
 *
 * Env required for Tempo:
 *   TEMPO_RECIPIENT_ADDRESS  – your Tempo wallet (receives pathUSD)
 *   MPP_SECRET_KEY           – HMAC secret (or falls back to STRIPE_SECRET_KEY)
 *
 * Env for Stripe (optional but recommended):
 *   STRIPE_SECRET_KEY
 *   STRIPE_PROFILE_ID
 *
 * NODE_ENV !== 'production' → Tempo testnet (Moderato, chainId 42431)
 * NODE_ENV === 'production'  → Tempo mainnet (chainId 4217)
 */

const Stripe = require('stripe');
const { Mppx, stripe: mppStripe, tempo } = require('mppx/express');

// ---------------------------------------------------------------------------
// Stripe client
// ---------------------------------------------------------------------------
const stripeClient = new Stripe(process.env.STRIPE_SECRET_KEY, {
  apiVersion: '2026-03-25.preview',
});

// ---------------------------------------------------------------------------
// pathUSD (same contract address on mainnet and Moderato testnet)
// ---------------------------------------------------------------------------
const PATH_USD = '0x20c0000000000000000000000000000000000000';
const isTestnet = process.env.NODE_ENV !== 'production';

// ---------------------------------------------------------------------------
// Early validation – fail loudly if misconfigured
// ---------------------------------------------------------------------------
function assertTempoConfig() {
  const missing = [];
  if (!process.env.TEMPO_RECIPIENT_ADDRESS) {
    missing.push('TEMPO_RECIPIENT_ADDRESS');
  }
  if (!process.env.MPP_SECRET_KEY && !process.env.STRIPE_SECRET_KEY) {
    missing.push('MPP_SECRET_KEY (or STRIPE_SECRET_KEY as fallback)');
  }
  if (missing.length) {
    console.warn(
      `⚠️  Tempo/MPP config incomplete — missing: ${missing.join(', ')}. ` +
        `402 challenges will still be issued but verification may fail.`
    );
  } else {
    console.log(
      `✅ Tempo configured → recipient=${process.env.TEMPO_RECIPIENT_ADDRESS.slice(0, 10)}… ` +
        `network=${isTestnet ? 'Moderato testnet (42431)' : 'mainnet (4217)'} currency=pathUSD`
    );
  }
}
assertTempoConfig();

// ---------------------------------------------------------------------------
// Build methods array (only register what is configured)
// mppx.charge({ amount }) later composes every registered method into one 402
// ---------------------------------------------------------------------------
const methods = [];

// 1. Stripe SPT (card + Link)
if (process.env.STRIPE_SECRET_KEY && process.env.STRIPE_PROFILE_ID) {
  methods.push(
    mppStripe.charge({
      client: stripeClient,
      networkId: process.env.STRIPE_PROFILE_ID,
      paymentMethodTypes: ['card', 'link'],
      decimals: 2,
    })
  );
  console.log('📌 Registered Stripe charge method');
} else {
  console.warn(
    '⚠️  Stripe charge method skipped (STRIPE_SECRET_KEY or STRIPE_PROFILE_ID missing)'
  );
}

// 2. Tempo pathUSD one-time charge (testnet when not production)
if (process.env.TEMPO_RECIPIENT_ADDRESS) {
  methods.push(
    tempo.charge({
      currency: PATH_USD, // pathUSD TIP-20
      decimals: 6, // pathUSD has 6 decimals
      recipient: process.env.TEMPO_RECIPIENT_ADDRESS,
      testnet: isTestnet, // true → Moderato (42431), false → mainnet (4217)
      // mode: 'pull' is default (server can later add feePayer for gas sponsorship)
    })
  );
  console.log(
    `📌 Registered Tempo pathUSD charge method (${isTestnet ? 'testnet' : 'mainnet'})`
  );
} else {
  console.warn(
    '⚠️  Tempo charge method skipped (TEMPO_RECIPIENT_ADDRESS missing)'
  );
}

// Optional later – Tempo Sessions (pay-as-you-go channels):
// const { Store } = require('mppx');
// const { privateKeyToAccount } = require('viem/accounts');
// methods.push(
//   tempo.session({
//     account: privateKeyToAccount(process.env.TEMPO_SERVER_PRIVATE_KEY),
//     chainId: isTestnet ? 42431 : 4217,
//     currency: PATH_USD,
//     store: Store.memory(),
//   })
// );

// ---------------------------------------------------------------------------
// Create Mppx instance
// ---------------------------------------------------------------------------
const mppx = Mppx.create({
  secretKey: process.env.MPP_SECRET_KEY || process.env.STRIPE_SECRET_KEY,
  methods,
  // realm is auto-detected; override with MPP_REALM or realm: 'api.yourdomain.com'
});

// Diagnostic logs
console.log('🔍 mppx methods available:', Object.keys(mppx || {}));
console.log('   has charge:', typeof mppx?.charge === 'function');
console.log('   has tempo:', !!mppx?.tempo);
console.log('   has stripe:', !!mppx?.stripe);

module.exports = {
  mppx,
  stripeClient,
  PATH_USD,
  isTestnet,
};
