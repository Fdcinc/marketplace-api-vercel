const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models/users');
const Blacklist = require('../models/blacklist');
const { protect } = require('../middleware/auth');

const router = express.Router();

// ──── LOGIN (With Brute Force Protection) ──────────────────
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, error: 'Email and password are required' });
  }

  try {
    const user = await User.findOne({ email: email.toLowerCase() })
      .select('+passwordHash +loginAttempts +lockUntil');

    if (!user) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    // Check if account is locked
    if (user.lockUntil && user.lockUntil > Date.now()) {
      const remainingMinutes = Math.ceil((user.lockUntil - Date.now()) / 60000);
      return res.status(403).json({ 
        success: false, 
        error: `Account locked. Try again in ${remainingMinutes} minutes.` 
      });
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);

    if (!isMatch) {
      user.loginAttempts += 1;
      if (user.loginAttempts >= 5) {
        user.lockUntil = Date.now() + 30 * 60 * 1000; 
      }
      await user.save({ validateBeforeSave: false });
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    // Success: Reset counters
    user.loginAttempts = 0;
    user.lockUntil = undefined;
    user.lastLoginAt = Date.now();
    await user.save({ validateBeforeSave: false });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });

    res.json({
      success: true,
      token,
      user: user.toJSON() // Use the helper method from your model
    });
  } catch (err) {
    console.error('Login Error:', err.message);
    // Explicitly send response instead of using next(err)
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// ──── REGISTER ─────────────────────────────────────────────
router.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password || password.length < 8) {
    return res.status(400).json({ success: false, error: 'Valid name, email, and 8-char password required' });
  }

  try {
    const user = await User.create({
      name,
      email: email.toLowerCase(),
      passwordHash: password, 
      role: 'customer'
    });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });

    res.status(201).json({
      success: true,
      token,
      user: user.toJSON()
    });
  } catch (err) {
    if (err.code === 11000) return res.status(409).json({ success: false, error: 'Email already in use' });
    res.status(500).json({ success: false, error: 'Registration failed' });
  }
});

// ──── GET CURRENT USER ─────────────────────────────────────
router.get('/me', protect, async (req, res) => {
  // Since 'protect' middleware attaches the user to req.user
  res.json({
    success: true,
    user: req.user // .toJSON() is called automatically by Express
  });
});

// ──── FORGOT PASSWORD ──────────────────────────────────────
router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ success: false, error: 'Email is required' });

  try {
    const user = await User.findOne({ email: email.trim().toLowerCase() });
    
    if (!user) {
      return res.json({ success: true, message: 'If the email exists, a reset link has been sent' });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    user.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
    user.passwordResetExpires = Date.now() + 3600000; 

    await user.save({ validateBeforeSave: false });

    if (process.env.NODE_ENV !== 'production') {
      console.log('DEBUG ✅ Reset Token:', resetToken);
    }

    res.json({ success: true, message: 'If the email exists, a reset link has been sent' });
  } catch (err) {
    console.log("FULL ERROR STACK:", err.stack); // This will tell you the exact line number
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// ──── RESET PASSWORD ───────────────────────────────────────
router.patch('/reset-password/:token', async (req, res) => {
  const { password } = req.body;
  if (!password || password.length < 8) {
    return res.status(400).json({ success: false, error: 'Password must be at least 8 characters' });
  }

  try {
    const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');
    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!user) return res.status(400).json({ success: false, error: 'Token is invalid or expired' });

    user.passwordHash = password;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.json({ success: true, message: 'Password reset successful', token });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Reset failed' });
  }
});

// ──── LOGOUT ───────────────────────────────────────────────
router.post('/logout', protect, async (req, res) => {
  try {
    const token = req.headers.authorization.split(' ')[1];
    await Blacklist.create({ 
      token, 
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) 
    });

    res.json({ success: true, message: 'Logged out successfully' });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Logout failed' });
  }
});

module.exports = router;