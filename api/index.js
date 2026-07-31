/**
 * @file index.js
 * @description Marketplace API entry point with MPP (Machine Payments Protocol) support.
 */

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '../.env') });

const express = require('express');
const cors = require('cors');
const Stripe = require('stripe');
const { Mppx, stripe: mppStripe } = require('mppx/express');

const connectDB = require('./v1/config/db');
const authRoutes = require('./v1/routes/auth');
const authController = require('./v1/controllers/authController');
const agentRoutes = require('./v1/routes/agent');

const app = express();

// ====================== CORS ======================
app.use(cors({
  origin: [
    'http://localhost:5173',
    'http://127.0.0.1:5173',
    'http://localhost:3000'
  ],
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'x-platform-secret',
    'x-auth-source'
  ],
  credentials: true
}));

// ====================== STRIPE WEBHOOK ======================
app.post(
  '/api/v1/webhooks',
  express.raw({ type: 'application/json' }),
  authController.handleStripeWebhook
);

// ====================== MPP SETUP ======================
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

// IMPORTANT: Register the paid route BEFORE express.json()
app.post(
  '/api/v1/auth/mpp-data',
  mppx.charge({
    amount: '0.50',
    currency: 'usd',
    decimals: 2,
  }),
  (req, res) => {
    res.json({
      success: true,
      message: 'Machine payment verified! Premium marketplace payload delivered.',
      paymentDetails: req.payment || {},
    });
  }
);

// ====================== BODY PARSER ======================
app.use(express.json());

// ====================== ROUTES ======================
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/agent', agentRoutes);

app.get('/', (req, res) => {
  res.json({ message: 'Marketplace API is running locally' });
});

// ====================== OPENAPI DISCOVERY (Forced / Reliable) ======================
app.get('/openapi.json', (req, res) => {
  res.json({
    openapi: '3.1.0',
    info: {
      title: 'Marketplace API',
      version: '1.0.0',
      description: 'Marketplace API with Machine Payments Protocol (MPP) support via Stripe',
    },
    paths: {
      '/api/v1/auth/mpp-data': {
        post: {
          summary: 'MPP Paid Endpoint',
          description: 'Requires payment of $0.50 via Machine Payments Protocol (Stripe)',
          operationId: 'mppData',
          tags: ['MPP'],
          responses: {
            '200': {
              description: 'Payment successful',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      success: { type: 'boolean' },
                      message: { type: 'string' },
                      paymentDetails: { type: 'object' },
                    },
                  },
                },
              },
            },
            '402': {
              description: 'Payment Required – returns WWW-Authenticate: Payment challenge',
            },
          },
        },
      },
    },
  });
});

// ====================== ERROR HANDLER ======================
app.use((err, req, res, next) => {
  console.error('🔥 Global Error:', err.stack);
  res.status(500).json({ success: false, error: 'Internal Server Error' });
});

// ====================== START SERVER ======================
const PORT = process.env.PORT || 5000;

if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`✅ CORS allowed for http://localhost:5173`);
  });
}

module.exports = app;