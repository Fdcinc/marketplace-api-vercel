const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models/users');
const Blacklist = require('../models/blacklist');
const { protect } = require('../middleware/auth'); // Ensure this path is correct

const router = express.Router();

// ──── LOGIN ────────────────────────────────────────────────
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, error: 'Email and password are required' });
  }

  try {
    const user = await User.findOne({ email }).select('+passwordHash');

    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });

    res.json({
      success: true,
      token,
      user: { id: user._id, name: user.name, email: user.email, role: user.role }
    });
  } catch (err) {
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
      user: { id: user._id, name: user.name, email: user.email, role: user.role }
    });
  } catch (err) {
    if (err.code === 11000) return res.status(409).json({ success: false, error: 'Email already in use' });
    res.status(500).json({ success: false, error: 'Registration failed' });
  }
});

// ──── GET CURRENT USER ─────────────────────────────────────
router.get('/me', protect, async (req, res) => {
  res.json({
    success: true,
    user: {
      id: req.user._id,
      name: req.user.name,
      email: req.user.email,
      role: req.user.role,
      status: req.user.status
    }
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
    user.passwordResetExpires = Date.now() + 3600000; // 1 hour

    await user.save();
    console.log('✅ Reset Token:', resetToken);

    res.json({ success: true, message: 'If the email exists, a reset link has been sent' });
  } catch (err) {
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
    // protect middleware ensures authorization header exists and is valid
    const token = req.headers.authorization.split(' ')[1];
    await Blacklist.create({ token });

    res.json({ success: true, message: 'Logged out successfully' });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Logout failed' });
  }
});


module.exports = router;