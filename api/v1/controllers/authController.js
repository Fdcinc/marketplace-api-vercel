const User = require('../models/users');
const Blacklist = require('../models/blacklist');
const jwt = require('jsonwebtoken');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const connectDB = require('../config/db');

// --- HELPER: Sync Stripe Customer ---
const ensureStripeCustomer = async (user) => {
  if (user.stripeCustomerId) return user.stripeCustomerId;

  try {
    console.log(`👤 Syncing Stripe Customer for ${user.email}...`);
    const customer = await stripe.customers.create({
      email: user.email,
      name: user.name || 'User',
      metadata: { source: 'marketplace_api_sync' }
    });
    
    user.stripeCustomerId = customer.id;
    await user.save();
    console.log(`✅ Stripe Customer ${customer.id} synced to user ${user.email}`);
    return customer.id;
  } catch (err) {
    console.error(`❌ Stripe Sync Error for ${user.email}:`, err.message);
    throw err;
  }
};

const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '1d',
  });
};

// --- STRIPE WEBHOOK ---
exports.handleStripeWebhook = async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error(`⚠️ Webhook signature verification failed: ${err.message}`);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  console.log(`🔔 Webhook received: ${event.type}`);

  if (event.type === 'billing.meter.summary_updated') {
    const summary = event.data.object;
    console.log(`📊 Stripe Meter Update: Customer ${summary.customer} reached ${summary.aggregate_value}`);
    
    await connectDB();
    const updatedUser = await User.findOneAndUpdate(
      { stripeCustomerId: summary.customer },
      { currentUsage: summary.aggregate_value, usageLastUpdated: new Date() },
      { returnDocument: 'after' }
    );

    if (updatedUser) {
      console.log(`✅ MongoDB Synced: ${updatedUser.email} local count updated to ${summary.aggregate_value}`);
    }
  }
  res.json({ received: true });
};

// --- AUTH LOGIC ---
exports.register = async (req, res) => {
  await connectDB();
  try {
    const { name, email, password } = req.body;
    const normalizedEmail = email.toLowerCase().trim();
    
    const existingUser = await User.findOne({ email: normalizedEmail });
    if (existingUser) return res.status(400).json({ success: false, error: 'Email already exists' });

    const user = await User.create({ name, email: normalizedEmail, passwordHash: password });
    await ensureStripeCustomer(user);

    const token = signToken(user._id);
    const userResponse = user.toObject();
    delete userResponse.passwordHash;
    res.status(201).json({ success: true, token, user: userResponse });
  } catch (err) {
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

    await ensureStripeCustomer(user);
    console.log(`🔑 User logged in: ${user.email}`);
    
    const token = signToken(user._id);
    res.json({ success: true, token, user: { id: user._id, name: user.name, email: user.email, stripeCustomerId: user.stripeCustomerId } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

// --- MIDDLEWARE ---
exports.trackUsage = async (req, res, next) => {
  try {
    if (!req.user) {
        console.log("ℹ️ TrackUsage: No user found on request, skipping.");
        return next();
    }
    
    await connectDB();
    const user = await User.findById(req.user.id);
    if (!user) return next();

    console.log(`🔍 Tracking usage for ${user.email}...`);
    await ensureStripeCustomer(user);

    const HARD_LIMIT = parseInt(process.env.USAGE_HARD_LIMIT) || 1000;
    if ((user.currentUsage || 0) >= HARD_LIMIT) {
      console.log(`🚫 Guardrail: ${user.email} blocked at ${user.currentUsage}`);
      return res.status(429).json({ success: false, error: 'Limit reached.' });
    }

    console.log(`📡 Sending 'api_request' event to Stripe for ${user.stripeCustomerId}...`);
    stripe.billing.meterEvents.create({
      event_name: 'api_request',
      payload: { stripe_customer_id: user.stripeCustomerId, value: '1' },
    }).catch(e => console.error("❌ Stripe Ingestion Error:", e.message));

    const updatedUser = await User.findByIdAndUpdate(req.user.id, { $inc: { currentUsage: 1 } }, { returnDocument: 'after' });
    console.log(`💾 Local Cache Updated: ${updatedUser.email} count is now ${updatedUser.currentUsage}`);
    
    next();
  } catch (err) {
    console.error('❌ TrackUsage Error:', err.message);
    next();
  }
};

// --- REMAINING METHODS ---
exports.getMe = async (req, res) => {
  await connectDB();
  const user = await User.findById(req.user.id).select('-passwordHash');
  res.json({ success: true, user });
};

exports.getUsage = async (req, res) => {
  console.log(`📥 Fetching dashboard data for User ID: ${req.user.id}`);
  await connectDB();
  const user = await User.findById(req.user.id);
  
  if (!user || !user.stripeCustomerId) {
     console.log("ℹ️ GetUsage: No user/Stripe ID, returning zeros.");
     return res.json({ success: true, data: { amount_due: 0, quantity: 0, currency: 'EUR', period_end: '--' }});
  }

  console.log(`🔎 Querying Stripe for customer: ${user.stripeCustomerId}`);
  let amountDue = 0, currency = 'EUR', periodEnd = '--';
  try {
    const inv = await stripe.invoices.retrieveUpcoming({ customer: user.stripeCustomerId });
    amountDue = (inv.amount_remaining || 0) / 100;
    currency = (inv.currency || 'EUR').toUpperCase();
    periodEnd = new Date(inv.next_payment_attempt * 1000).toLocaleDateString();
    console.log(`💰 Stripe Invoice Found: ${amountDue} ${currency}`);
  } catch (e) { 
    console.log("ℹ️ GetUsage: No upcoming invoice found (Normal for new users)."); 
  }

  res.json({ success: true, data: { amount_due: amountDue, currency, quantity: user.currentUsage || 0, period_end: periodEnd } });
};

exports.resetUsage = async (req, res) => {
  await connectDB();
  const user = await User.findByIdAndUpdate(req.user.id, { currentUsage: 0 }, { returnDocument: 'after' });
  console.log(`🔄 Usage reset for ${user.email} → 0`);
  res.json({ success: true, currentUsage: 0 });
};

exports.logout = async (req, res) => {
  await connectDB();
  const token = req.headers.authorization?.split(' ')[1];
  if (token) await Blacklist.create({ token });
  res.status(200).json({ success: true, message: 'Logged out' });
};

exports.getAllUsers = async (req, res) => {
  await connectDB();
  const users = await User.find().select('-passwordHash');
  res.status(200).json({ success: true, data: users });
};

exports.getUserById = async (req, res) => {
  await connectDB();
  const user = await User.findById(req.params.id).select('-passwordHash');
  res.status(200).json({ success: true, user });
};

exports.updateMe = async (req, res) => {
  await connectDB();
  const user = await User.findByIdAndUpdate(req.user.id, req.body, { returnDocument: 'after' }).select('-passwordHash');
  res.status(200).json({ success: true, user });
};

exports.updateUser = async (req, res) => {
  await connectDB();
  const user = await User.findByIdAndUpdate(req.params.id, req.body, { returnDocument: 'after' }).select('-passwordHash');
  res.status(200).json({ success: true, user });
};

exports.deleteMe = async (req, res) => {
  await connectDB();
  await User.findByIdAndUpdate(req.user.id, { status: 'inactive' });
  res.status(204).json({ success: true });
};