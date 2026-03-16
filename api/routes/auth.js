const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const User = require('../models/users');
const Blacklist = require('../models/blacklist');
const connectDB = require('../config/db'); 
const { protect } = require('../middleware/auth');

const router = express.Router();

// ──── REGISTER ────
router.post('/register', async (req, res) => {
  try {
    await connectDB();
    const { name, email, password } = req.body;

    // 1. Basic validation check
    if (!name || !email || !password) {
      return res.status(400).json({ 
        success: false, 
        error: 'Missing fields. Name, email, and password are required.' 
      });
    }

    // 2. Create User 
    // Note: ensure 'passwordHash' matches the field name in your models/users.js
    const user = await User.create({
      name,
      email: email.toLowerCase().trim(),
      passwordHash: password 
    });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });

    // Remove passwordHash from response object
    const userResponse = user.toObject();
    delete userResponse.passwordHash;

    res.status(201).json({ 
      success: true, 
      token, 
      user: userResponse 
    });

  } catch (err) {
    // CRITICAL: Log the full error to your terminal so you can see what failed
    console.error("REGISTRATION ERROR DETAILS:", err);

    if (err.code === 11000) {
      return res.status(400).json({ success: false, error: 'Email already exists' });
    }

    // Send the actual error message back to help you debug locally
    res.status(500).json({ 
      success: false, 
      error: 'Registration failed', 
      details: err.message 
    });
  }
});

// ──── LOGIN ────
router.post('/login', async (req, res) => {
  try {
    await connectDB();
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'Email and password required' });
    }

    const user = await User.findOne({ email: email.toLowerCase().trim() }).select('+passwordHash');

    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });

    res.json({ 
      success: true, 
      token, 
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (err) {
    console.error("LOGIN ERROR:", err);
    res.status(500).json({ success: false, error: 'Login failed', details: err.message });
  }
});

module.exports = router;

module.exports = router;