const User = require('../models/users');
const Blacklist = require('../models/blacklist');
const jwt = require('jsonwebtoken');

/**
 * Helper to generate JWT
 */
const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '1d',
  });
};

// ──── REGISTER ────
exports.register = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ success: false, error: 'Missing fields' });
    }

    const user = await User.create({
      name,
      email: email.toLowerCase().trim(),
      passwordHash: password 
    });

    const token = signToken(user._id);
    const userResponse = user.toObject();
    delete userResponse.passwordHash;

    res.status(201).json({ success: true, token, user: userResponse });
  } catch (err) {
    if (err.code === 11000) return res.status(400).json({ success: false, error: 'Email already exists' });
    res.status(500).json({ success: false, error: err.message });
  }
};

// ──── LOGIN ────
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'Email and password required' });
    }

    const user = await User.findOne({ email: email.toLowerCase().trim() }).select('+passwordHash');

    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    const token = signToken(user._id);

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
    res.status(500).json({ success: false, error: 'Login failed', details: err.message });
  }
};

// ──── ME (Current User) ────
exports.getMe = async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-passwordHash');
    res.json({ success: true, user });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

// ──── LOGOUT ────
exports.logout = async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(400).json({ success: false, error: 'No token found' });

    await Blacklist.create({ token });

    res.status(200).json({ success: true, message: 'Logged out successfully' });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Logout failed' });
  }
};

// ──── ADMIN: GET ALL USERS (CRITICAL: Added this to fix the crash) ────
exports.getAllUsers = async (req, res) => {
  try {
    const users = await User.find().select('-passwordHash');
    res.status(200).json({
      success: true,
      count: users.length,
      data: users
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to fetch users' });
  }
};