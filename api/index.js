/**
 * @file index.js
 * @description Marketplace API entry point with MPP setup extracted to config.
 */

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '../.env') });

const express = require('express');
const cors = require('cors');

const connectDB = require('./v1/config/db');
const { mppx } = require('./v1/config/mpp'); // ✅ Imported from clean config file
const { getOpenApiSpec } = require('./v1/config/openapi'); // ✅ Imported from clean config file
const authRoutes = require('./v1/routes/auth');
const { handleStripeWebhook } = require('./v1/controllers/webhook');
const agentRoutes = require('./v1/routes/agent');
const billingRoutes = require('./v1/routes/billing');
const mppRoutes = require('./v1/routes/mpp');
const mcpRoutes = require('./v1/routes/mcp');

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
  handleStripeWebhook
);

// ====================== MPP ROUTES ======================
// Important: mount before express.json() if you want maximum header safety
app.use('/api/v1/mpp', mppRoutes);

// ====================== BODY PARSER ======================
app.use(express.json());

// ====================== ROUTES ======================
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/agent', agentRoutes);
app.use('/api/v1/billing', billingRoutes);
app.use('/api/v1/mcp', mcpRoutes);
app.get('/', (req, res) => {
  res.json({ message: 'Marketplace API is running locally' });
});

// ====================== OPENAPI DISCOVERY ======================
app.get('/openapi.json', (req, res) => {
  res.json(getOpenApiSpec());
});

// ====================== MPP DISCOVERY (ROOT LEVEL) ======================
app.get('/.well-known/mpp', (req, res) => {
  const baseUrl = `${req.protocol}://${req.get('host')}`;
  res.json({
    service: 'Marketplace API',
    version: '1.0.0',
    description: 'Premium data and insights with MPP payment support',
    endpoints: [
      {
        path: '/api/v1/mpp/mpp-data',
        method: 'POST',
        amount: '0.50',
        currency: 'usd',
        description: 'Premium marketplace data payload.',
        paymentMethods: ['card', 'link', 'tempo'],
        'x-agent-id': 'optional',
      },
      {
        path: '/api/v1/mpp/premium',
        method: 'GET',
        amount: '0.25',
        currency: 'usd',
        description: 'Premium marketplace insights.',
        paymentMethods: ['card', 'link', 'tempo'],
        'x-agent-id': 'optional',
      },
    ],
    mcp: {
      url: `${baseUrl}/api/v1/mcp/tools`,
      description: 'MCP tools for AI agents',
    },
    openapi: {
      url: `${baseUrl}/openapi.json`,
      description: 'OpenAPI spec for developers',
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

async function start() {
  try {
    await connectDB();

    if (process.env.NODE_ENV !== 'production') {
      app.listen(PORT, '0.0.0.0', () => {
        console.log(`🚀 Server running on http://localhost:${PORT}`);
        console.log(`✅ CORS allowed for http://localhost:5173`);
      });
    }
  } catch (err) {
    console.error('❌ Failed to start server:', err.message);
    process.exit(1);
  }
}

start();

console.log('Stripe key mode:', process.env.STRIPE_SECRET_KEY?.startsWith('sk_test_') ? 'TEST' : 'LIVE');
console.log('Stripe Secret Key starts with:', process.env.STRIPE_SECRET_KEY?.substring(0, 8));

module.exports = app;