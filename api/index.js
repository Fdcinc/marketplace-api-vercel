require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors'); // Highly recommended for Vercel
const connectDB = require('./config/db');
const { protect, restrictTo } = require('./middleware/auth');
const authRoutes = require('./routes/auth');
const rateLimit = require('express-rate-limit');

const app = express();

// ──── MIDDLEWARE ────
app.use(cors()); // Allow cross-origin requests
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Trust Vercel's proxy headers
app.set('trust proxy', 1); 

// ──── DATABASE ────
// In Serverless, we call this once; the singleton in your db.js handles the rest
connectDB();

// ──── RATE LIMITING ────
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true, 
  legacyHeaders: false,
  // This line is key to stopping the Vercel crash you saw
  validate: { xForwardedForHeader: false }, 
});

// Apply limiter to all /api routes
app.use('/api/', limiter);

// ──── ROUTES ────

// Base route for a clean status check
app.get('/', (req, res) => {
  res.status(200).json({ 
    success: true, 
    message: 'Marketplace API is Live',
    env: process.env.NODE_ENV || 'development'
  });
});

app.use('/api/auth', authRoutes);

// Health check route
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    dbConnected: mongoose.connection.readyState === 1,
  });
});

// Protected Admin Route Example
app.get(
  '/api/users',
  protect,
  restrictTo('admin', 'superadmin'),
  async (req, res) => {
    try {
      const User = require('./models/users');
      const users = await User.find({}).select('-passwordHash').lean();
      res.json({ success: true, count: users.length, data: users });
    } catch (err) {
      res.status(500).json({ success: false, error: 'Server error' });
    }
  }
);

// ──── SERVERLESS EXPORT ────
// Important: Vercel expects the app to be exported, not app.listen()
if (process.env.NODE_ENV !== 'production') {
  const PORT = process.env.PORT || 5000;
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

module.exports = app;