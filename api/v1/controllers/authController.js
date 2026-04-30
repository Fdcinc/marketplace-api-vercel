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

// --- STRIPE WEBHOOK (The "Truth" Sync) ---
exports.handleStripeWebhook = async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    console.error(`⚠️ Webhook signature verification failed: ${err.message}`);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  console.log(`🔔 Webhook received: ${event.type}`);

  if (event.type === 'billing.meter.summary_updated') {
    const summary = event.data.object;
    console.log(`📊 Stripe Meter Update: Customer ${summary.customer} reached ${summary.aggregate_value}`);
    
    try {
      await connectDB();
      const updatedUser = await User.findOneAndUpdate(
        { stripeCustomerId: summary.customer },
        { 
          currentUsage: summary.aggregate_value,
          usageLastUpdated: new Date()
        },
        { returnDocument: 'after' } // Modern Mongoose standard
      );

      if (updatedUser) {
        console.log(`✅ MongoDB Synced: ${updatedUser.email} local count updated to ${summary.aggregate_value}`);
      } else {
        console.warn(`⚠️ Webhook Warning: No user found with Stripe ID ${summary.customer}`);
      }
    } catch (dbErr) {
      console.error('❌ Webhook DB Sync Error:', dbErr.message);
    }
  }

  res.json({ received: true });
};

// --- AUTH LOGIC ---
exports.register = async (req, res) => {
  await connectDB();
  let customer;
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ success: false, error: 'Missing fields' });

    const normalizedEmail = email.toLowerCase().trim();
    const existingUser = await User.findOne({ email: normalizedEmail });
    if (existingUser) return res.status(400).json({ success: false, error: 'Email already exists' });

    console.log(`👤 Creating Stripe Customer for ${normalizedEmail}...`);
    customer = await stripe.customers.create({
      email: normalizedEmail,
      name: name,
      metadata: { source: 'marketplace_api' }
    });

    await stripe.subscriptions.create({
      customer: customer.id,
      items: [{ price: process.env.STRIPE_PRICE_ID }],
    });

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
    if (customer && customer.id) await stripe.customers.del(customer.id);
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
    console.log(`🔑 User logged in: ${user.email}`);
    res.json({ success: true, token, user: { id: user._id, name: user.name, email: user.email, role: user.role, stripeCustomerId: user.stripeCustomerId, currentUsage: user.currentUsage } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

// --- MIDDLEWARE & SECURITY GUARDRAIL ---
exports.trackUsage = async (req, res, next) => {
  try {
    if (!req.user) {
      console.log("ℹ️ TrackUsage: No user found on request, skipping.");
      return next();
    }
    
    console.log(`🔍 Tracking usage for ${req.user.email || req.user.id}...`);
    
    if (!req.user.stripeCustomerId) {
      console.log("ℹ️ TrackUsage: No Stripe ID found, skipping ingestion.");
      return next();
    }

    await connectDB();
    const HARD_LIMIT = 500;
    const user = await User.findById(req.user.id);

    if (!user) {
      console.log("ℹ️ TrackUsage: User not found in database.");
      return next();
    }

    // 1. Guardrail Check
    if ((user.currentUsage || 0) >= HARD_LIMIT) {
      console.log(`🚫 Guardrail: ${user.email} blocked at ${user.currentUsage}`);
      return res.status(429).json({
        success: false,
        error: 'Usage limit reached. Please upgrade your plan.',
        currentUsage: user.currentUsage,
        limit: HARD_LIMIT
      });
    }

    // 2. Fire and forget to Stripe
    console.log(`📡 Sending 'api_request' event to Stripe for ${user.stripeCustomerId}...`);
    stripe.billing.meterEvents.create({
      event_name: 'api_request',
      payload: { stripe_customer_id: user.stripeCustomerId, value: '1' },
    }).catch(e => console.error("❌ Stripe Ingestion Error:", e.message));

    // 3. Increment local cache (Atomic Update)
    // Deprecation fixed: using returnDocument: 'after'
    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      { $inc: { currentUsage: 1 } }, 
      { returnDocument: 'after' } 
    );

    if (updatedUser) {
        console.log(`💾 Local Cache Updated: ${updatedUser.email} count is now ${updatedUser.currentUsage}`);
    }

    next();
  } catch (err) {
    console.error('❌ TrackUsage Error:', err.message);
    next();
  }
};

// --- REMAINING METHODS ---
exports.getMe = async (req, res) => {
  await connectDB();
  try {
    const user = await User.findById(req.user.id).select('-passwordHash');
    res.json({ success: true, user });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

exports.getUsage = async (req, res) => {
  try {
    console.log(`📥 Fetching dashboard data for User ID: ${req.user.id}`);
    await connectDB();
    const user = await User.findById(req.user.id);
    
    if (!user || !user.stripeCustomerId) {
       console.log("ℹ️ GetUsage: No user/Stripe ID, returning zeros.");
       return res.status(200).json({ 
         success: true, 
         data: { amount_due: 0, quantity: 0, currency: 'EUR', period_end: '--' } 
       });
    }
    
    console.log(`🔎 Querying Stripe for customer: ${user.stripeCustomerId}`);
    let amountDue = 0;
    let currency = 'EUR';
    let periodEnd = '--';

    try {
      const upcomingInvoice = await stripe.invoices.retrieveUpcoming({
        customer: user.stripeCustomerId,
      });
      amountDue = (upcomingInvoice.amount_remaining || 0) / 100;
      currency = (upcomingInvoice.currency || 'EUR').toUpperCase();
      periodEnd = new Date(upcomingInvoice.next_payment_attempt * 1000).toLocaleDateString();
      console.log(`💰 Stripe Invoice Found: ${amountDue} ${currency}`);
    } catch (stripeErr) {
      console.log("ℹ️ GetUsage: No upcoming invoice found (Normal for new users).");
    }

    res.json({
      success: true,
      data: {
        amount_due: amountDue,
        currency: currency,
        quantity: user.currentUsage || 0,
        period_end: periodEnd,
      }
    });
  } catch (err) {
    console.error('❌ GetUsage Crash:', err.message);
    res.status(500).json({ success: false, error: 'Failed to retrieve usage' });
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
    res.status(500).json({ success: false, error: 'Failed' });
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
    const user = await User.findByIdAndUpdate(req.user.id, updates, { returnDocument: 'after' }).select('-passwordHash');
    res.status(200).json({ success: true, user });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

exports.updateUser = async (req, res) => {
  await connectDB();
  try {
    const user = await User.findByIdAndUpdate(req.params.id, req.body, { returnDocument: 'after' }).select('-passwordHash');
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