const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '../.env') });

const express = require('express');
const cors = require('cors');
const connectDB = require('./v1/config/db');
const authRoutes = require('./v1/routes/auth');
const authController = require('./v1/controllers/authController'); // Import controller for webhook

const app = express();

// 1. Initialize DB
connectDB();

// 2. Standard Middleware
app.use(cors());

/**
 * 3. STRIPE WEBHOOK ROUTE (CRITICAL PLACEMENT)
 * This must be defined BEFORE app.use(express.json())
 */
app.post(
  '/api/v1/webhooks',
  express.raw({ type: 'application/json' }),
  authController.handleStripeWebhook
);

// 4. Global JSON Parser (Now it's safe to use for all other routes)
app.use(express.json());

// 5. Routes
app.use('/api/v1/auth', authRoutes);

app.get('/', (req, res) => {
  res.json({ message: "Marketplace API is running locally" });
});

if (process.env.NODE_ENV !== 'production') {
  const PORT = process.env.PORT || 5000;
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://0.0.0.0:${PORT}`);
    console.log(`Webhook endpoint active at http://localhost:${PORT}/api/v1/webhooks`);
  });
}

module.exports = app;