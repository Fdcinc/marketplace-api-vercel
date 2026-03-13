require('dotenv').config({ path: './src/.env' });

const express = require('express');
const connectDB = require('./config/db');
const { protect, restrictTo } = require('./middleware/auth');
const authRoutes = require('./routes/auth');
const rateLimit = require('express-rate-limit');

const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Connect to DB
connectDB();

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Routes
app.use('/api/auth', authRoutes);

// Protected route example
app.get(
  '/api/users',
  protect,
  restrictTo('admin', 'superadmin'),
  async (req, res) => {
    try {
      const users = await require('./models/users')
        .find({})
        .select('-passwordHash -__v -loginAttempts -schemaVersion')
        .lean();

      res.json({
        success: true,
        count: users.length,
        data: users,
      });
    } catch (err) {
      console.error('Users error:', err.message);
      res.status(500).json({ success: false, error: 'Server error' });
    }
  }
);

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    uptime: process.uptime(),
    dbConnected: mongoose.connection.readyState === 1,
  });
});

const PORT = process.env.PORT || 5000;

const server = app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Closing server...');
  server.close(() => {
    console.log('Server closed.');
    process.exit(0);
  });
});