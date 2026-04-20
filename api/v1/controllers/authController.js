const User = require('../models/users');
const Blacklist = require('../models/blacklist');
const jwt = require('jsonwebtoken');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const connectDB = require('../config/db');

const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '1d',
  });
};

exports.register = async (req, res) => {
  await connectDB();
  let customer;
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ success: false, error: 'Missing fields' });

    const normalizedEmail = email.toLowerCase().trim();

    // 1. PRE-CHECK: Prevent duplicate Stripe customers
    const existingUser = await User.findOne({ email: normalizedEmail });
    if (existingUser) {
      return res.status(400).json({ success: false, error: 'Email already exists' });
    }

    // 2. CREATE STRIPE CUSTOMER
    customer = await stripe.customers.create({
      email: normalizedEmail,
      name: name,
      metadata: { source: 'marketplace_api' }
    });

    // 3. ATTACH SUBSCRIPTION
    await stripe.subscriptions.create({
      customer: customer.id,
      items: [{ price: process.env.STRIPE_PRICE_ID }],
    });

    // 4. CREATE DATABASE USER
    const user = await User.create({
      name,
      email: normalizedEmail,
      passwordHash: password,
      stripeCustomerId: customer.id 
    });

    const token = signToken(user._id);
    const userResponse = user.toObject();
    delete userResponse.passwordHash;

    res.status(201).json({ success: true, token, user: userResponse });
  } catch (err) {
    // If Stripe customer was created but DB save failed, delete the Stripe customer
    if (customer && customer.id) {
      await stripe.customers.del(customer.id);
    }
    res.status(500).json({ success: false, error: err.message });
  }
};

exports.login = async (req, res) => {
  await connectDB();
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email: email.toLowerCase().trim() }).select('+passwordHash');
    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }
    const token = signToken(user._id);
    res.json({ success: true, token, user: { id: user._id, name: user.name, email: user.email, role: user.role, stripeCustomerId: user.stripeCustomerId } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

exports.getMe = async (req, res) => {
  await connectDB();
  try {
    const user = await User.findById(req.user.id).select('-passwordHash');
    res.json({ success: true, user });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

exports.trackUsage = async (req, res, next) => {
  try {
    if (req.user && req.user.stripeCustomerId) {
      await stripe.billing.meterEvents.create({
        event_name: 'api_request',
        payload: {
          stripe_customer_id: req.user.stripeCustomerId,
          value: '1',
        },
      });
      console.log(`✅ Usage tracked for: ${req.user.stripeCustomerId}`);
    }
    next();
  } catch (err) {
    console.error('❌ Usage tracking failed:', err.message);
    next();
  }
};

exports.logout = async (req, res) => {
  await connectDB();
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (token) await Blacklist.create({ token });
    res.status(200).json({ success: true, message: 'Logged out' });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Logout failed' });
  }
};

exports.getAllUsers = async (req, res) => {
  await connectDB();
  try {
    const users = await User.find().select('-passwordHash');
    res.status(200).json({ success: true, count: users.length, data: users });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to fetch users' });
  }
};

exports.getUserById = async (req, res) => {
  await connectDB();
  try {
    const user = await User.findById(req.params.id).select('-passwordHash');
    if (!user) return res.status(404).json({ success: false, error: 'User not found' });
    res.status(200).json({ success: true, user });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

exports.updateMe = async (req, res) => {
  await connectDB();
  try {
    const allowedUpdates = ['name', 'email'];
    const updates = {};
    Object.keys(req.body).forEach(key => { if (allowedUpdates.includes(key)) updates[key] = req.body[key]; });
    const user = await User.findByIdAndUpdate(req.user.id, updates, { new: true }).select('-passwordHash');
    res.status(200).json({ success: true, user });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

exports.updateUser = async (req, res) => {
  await connectDB();
  try {
    const user = await User.findByIdAndUpdate(req.params.id, req.body, { new: true }).select('-passwordHash');
    res.status(200).json({ success: true, user });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

exports.deleteMe = async (req, res) => {
  await connectDB();
  try {
    await User.findByIdAndUpdate(req.user.id, { status: 'inactive', deletedAt: new Date() });
    res.status(204).json({ success: true, data: null });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};