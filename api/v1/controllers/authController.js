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

  // 1. Existing Metering Update
  if (event.type === 'billing.meter.summary_updated') {
    const summary = event.data.object;
    await connectDB();
    const updatedUser = await User.findOneAndUpdate(
      { stripeCustomerId: summary.customer },
      { currentUsage: summary.aggregate_value, usageLastUpdated: new Date() },
      { returnDocument: 'after' }
    );
    if (updatedUser) console.log(`✅ MongoDB Synced Usage: ${updatedUser.email}`);
  } 
  
  // 2. NEW: Handle Credit Pack Purchases
  else if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    
    // Ensure we only process if this was a credit pack purchase
    // You can check session.metadata or simply apply logic here
    await connectDB();
    const updatedUser = await User.findOneAndUpdate(
      { stripeCustomerId: session.customer },
      { $inc: { credits: 1000 } }, // Adds 1000 credits to the user's balance
      { returnDocument: 'after' }
    );
    
    if (updatedUser) {
      console.log(`💰 Credits added to ${updatedUser.email}. New balance: ${updatedUser.credits}`);
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

    const user = await User.create({ name, email: normalizedEmail, passwordHash: password, credits: 1000 });
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
    // 1. FREE PATHS
    const freeRoutes = ['/api/v1/auth/me', '/api/v1/auth/usage'];
    if (freeRoutes.includes(req.originalUrl)) return next();

    if (!req.user) return next();
    
    await connectDB();
    const user = await User.findById(req.user.id);
    if (!user) return next();

    // 2. TRIAL LOGIC
    if (user.isTrial) {
      if (user.trialRequestsUsed < user.trialLimit) {
        // Increment trial usage
        await User.findByIdAndUpdate(user._id, { $inc: { trialRequestsUsed: 1 } });
        console.log(`✅ Trial usage for ${user.email}: ${user.trialRequestsUsed + 1}/${user.trialLimit}`);
        return next();
      } else {
        // Trial finished: Move to paid path or block
        await User.findByIdAndUpdate(user._id, { isTrial: false });
        // Fall through to standard credit check if they have migrated
      }
    }

    // 3. PAID GUARDRAIL: Block if no credits
    if ((user.credits || 0) <= 0) {
      console.log(`🚫 Blocked: ${user.email} has no credits.`);
      return res.status(402).json({ success: false, error: 'Insufficient credits. Please top up.' });
    }

    // 4. TRACKING: Only for paid requests
    stripe.billing.meterEvents.create({
      event_name: 'api_request',
      payload: { stripe_customer_id: user.stripeCustomerId, value: '1' },
    }).catch(e => console.error("❌ Stripe Ingestion Error:", e.message));

    await User.findByIdAndUpdate(req.user.id, { $inc: { credits: -1, currentUsage: 1 } });
    
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
  // Use a fallback to ensure we have a valid ID regardless of how the middleware set it
  const userId = req.user?.id || req.user?._id;

  if (!userId) {
    console.error("❌ GetUsage Error: No User ID found in request object.");
    return res.status(401).json({ success: false, error: "Unauthorized: User ID missing" });
  }

  console.log(`📥 Fetching dashboard data for User ID: ${userId}`);
  
  await connectDB();
  
  try {
    const user = await User.findById(userId);
    
    if (!user || !user.stripeCustomerId) {
       console.log("ℹ️ GetUsage: No user/Stripe ID found, returning zeros.");
       return res.json({ 
         success: true, 
         data: { amount_due: 0, quantity: 0, currency: 'EUR', period_end: '--' } 
       });
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

    res.json({ 
      success: true, 
      data: { 
        amount_due: amountDue, 
        currency, 
        quantity: user.currentUsage || 0, 
        period_end: periodEnd 
      } 
    });
    
  } catch (err) {
    console.error("❌ GetUsage Database Error:", err.message);
    res.status(500).json({ success: false, error: "Internal Server Error" });
  }
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

// Add this logic to your Auth flow to ensure new accounts are created
// --- JIT PROVISIONING (Link Auth0 to MongoDB) ---
exports.syncAuth0User = async (req, res) => {
  await connectDB();
  try {
    // This assumes your auth middleware already placed the Auth0 profile in req.user
    const { email, name } = req.user; 
    const normalizedEmail = email.toLowerCase().trim();

    let user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      console.log(`👤 JIT Provisioning: New user detected, creating record for ${normalizedEmail}`);
      user = await User.create({ 
        name: name || 'New User', 
        email: normalizedEmail, 
        passwordHash: 'AUTH0_MANAGED_ACCOUNT' 
      });
      await ensureStripeCustomer(user);
    }

    res.json({ success: true, user });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

module.exports = {
  ...module.exports, // Keeps existing exports
  ensureStripeCustomer
};