const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '../.env') });

const express = require('express');
const cors = require('cors');
const connectDB = require('./v1/config/db');
const authRoutes = require('./v1/routes/auth');
const authController = require('./v1/controllers/authController');

const app = express();

// ====================== CORS ======================
app.use(cors({
  origin: [
    'http://localhost:5173',
    'http://127.0.0.1:5173',
    'http://localhost:3000'
  ],
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-platform-secret'],
  credentials: true
}));

// ====================== STRIPE WEBHOOK ======================
app.post(
  '/api/v1/webhooks',
  express.raw({ type: 'application/json' }),
  authController.handleStripeWebhook
);

// ====================== BODY PARSER ======================
app.use(express.json());

// ====================== ROUTES ======================
app.use('/api/v1/auth', authRoutes);

app.get('/', (req, res) => {
  res.json({ message: "Marketplace API is running locally" });
});

// ====================== START SERVER ======================
const PORT = process.env.PORT || 8000;   // Default to 8000

if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`✅ CORS allowed for http://localhost:5173`);
  });
}

module.exports = app;