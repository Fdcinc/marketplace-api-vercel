const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models/users');
const Blacklist = require('../models/blacklist');
const { protect } = require('../middleware/auth');

const router = express.Router();

// Helper to send consistent error responses
const sendError = (res, status, message) => {
  return res.status(status).json({ success: false, error: message });
};

// Helper to send success responses
const sendSuccess = (res, status, data) => {
  return res.status(status).json({ success: true, ...data });
};

// ──── REGISTER ─────────────────────────────────────────────
router.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  if (!name?.trim() || !email?.trim() || !password || password.length < 8) {
    return sendError(res, 400, 'Name, valid email, and password (min 8 chars) are required');
  }

  try {
    await connectDB();
    // Hash password BEFORE creating user
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    const user = await User.create({
      name: name.trim(),
      email: email.trim().toLowerCase(),
      passwordHash,
      role: 'customer',
    });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });

    return sendSuccess(res, 201, {
      token,
      user: user.toJSON(), // or select fields manually if you prefer
    });
  } catch (err) {
    console.log('Route-level DB error:', err);
    if (err.code === 11000) {
      return sendError(res, 409, 'Email already in use');
    }
    console.error('Registration error:', err);
    return sendError(res, 500, 'Registration failed – please try again later');
  }
});

// ──── LOGIN (With Brute Force Protection) ──────────────────
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email?.trim() || !password) {
    return sendError(res, 400, 'Email and password are required');
  }

  try {
    await connectDB();
    const user = await User.findOne({ email: email.trim().toLowerCase() })
      .select('+passwordHash +loginAttempts +lockUntil');

    if (!user) {
      return sendError(res, 401, 'Invalid credentials');
    }

    // Account locked?
    if (user.lockUntil && user.lockUntil > Date.now()) {
      const remaining = Math.ceil((user.lockUntil - Date.now()) / 60000);
      return sendError(res, 403, `Account locked. Try again in ${remaining} minutes.`);
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);

    if (!isMatch) {
      user.loginAttempts = (user.loginAttempts || 0) + 1;

      if (user.loginAttempts >= 5) {
        user.lockUntil = Date.now() + 30 * 60 * 1000; // 30 minutes
      }

      await user.save({ validateBeforeSave: false });
      return sendError(res, 401, 'Invalid credentials');
    }

    // Success → reset security fields
    user.loginAttempts = 0;
    user.lockUntil = undefined;
    user.lastLoginAt = Date.now();
    await user.save({ validateBeforeSave: false });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });

    return sendSuccess(res, 200, {
      token,
      user: user.toJSON(),
    });
  } catch (err) {
    console.error('Login error:', err);
    return sendError(res, 500, 'Login failed – please try again');
  }
});

// ──── GET CURRENT USER ─────────────────────────────────────
router.get('/me', protect, async (req, res) => {
  try {
    // req.user already populated by protect middleware (without sensitive fields)
    return sendSuccess(res, 200, { user: req.user });
  } catch (err) {
    console.error('Get me error:', err);
    return sendError(res, 500, 'Failed to fetch user profile');
  }
});

// ──── LOGOUT ───────────────────────────────────────────────
router.post('/logout', protect, async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return sendError(res, 400, 'No token provided');
    }

    await Blacklist.create({
      token,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24h
    });

    return sendSuccess(res, 200, { message: 'Logged out successfully' });
  } catch (err) {
    console.error('Logout error:', err);
    return sendError(res, 500, 'Logout failed');
  }
});

// ──── FORGOT PASSWORD ──────────────────────────────────────
router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;

  if (!email?.trim()) {
    return sendError(res, 400, 'Email is required');
  }

  try {
    const user = await User.findOne({ email: email.trim().toLowerCase() });
    
    // Always return same message (security best practice)
    if (!user) {
      return sendSuccess(res, 200, {
        message: 'If the email exists, a reset link has been sent'
      });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    user.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
    user.passwordResetExpires = Date.now() + 60 * 60 * 1000; // 1 hour

    await user.save({ validateBeforeSave: false });

    // In production: send email here (nodemailer, resend, etc.)
    if (process.env.NODE_ENV !== 'production') {
      console.log('DEBUG Reset Token (only in dev):', resetToken);
    }

    return sendSuccess(res, 200, {
      message: 'If the email exists, a reset link has been sent'
    });
  } catch (err) {
    console.error('Forgot password error:', err);
    return sendError(res, 500, 'Server error');
  }
});

// ──── RESET PASSWORD ───────────────────────────────────────
router.patch('/reset-password/:token', async (req, res) => {
  const { password } = req.body;

  if (!password || password.length < 8) {
    return sendError(res, 400, 'Password must be at least 8 characters');
  }

  try {
    const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');

    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!user) {
      return sendError(res, 400, 'Invalid or expired reset token');
    }

    // Hash new password
    const salt = await bcrypt.genSalt(12);
    user.passwordHash = await bcrypt.hash(password, salt);

    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    // Optional: issue new token after reset
    const newToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });

    return sendSuccess(res, 200, {
      message: 'Password reset successful',
      token: newToken
    });
  } catch (err) {
    console.error('Reset password error:', err);
    return sendError(res, 500, 'Password reset failed');
  }
});

module.exports = router;