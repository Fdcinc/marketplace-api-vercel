require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose'); // Fixed: Explicitly required
const connectDB = require('./config/db');
const authRoutes = require('./routes/auth');
const rateLimit = require('express-rate-limit');

const app = express();

// ──── MIDDLEWARE ────
app.use(express.json());
app.set('trust proxy', 1); 

// ──── DATABASE ────
connectDB(); // Ensure this doesn't block the rest of the script

// ──── RATE LIMITING ────
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  validate: { xForwardedForHeader: false },
});
app.use('/api/', limiter);

// ──── ROUTES ────

// Health check (Safe version)
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    dbConnected: mongoose.connection?.readyState === 1,
  });
});

// Root route
app.get('/', (req, res) => {
  res.status(200).json({
    success: true,
    message: "Marketplace API is Live",
    dbStatus: mongoose.connection?.readyState === 1 ? "Connected" : "Disconnected"
  });
});

app.use('/api/auth', authRoutes);

// ──── SERVERLESS EXPORT ────
if (process.env.NODE_ENV !== 'production') {
  const PORT = process.env.PORT || 5000;
  app.listen(PORT, () => console.log(`Local server on ${PORT}`));
}

module.exports = app;