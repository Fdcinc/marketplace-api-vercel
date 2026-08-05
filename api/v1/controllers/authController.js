/**
 * @file controllers/authController.js
 * @description Auth, usage metering, Stripe webhook & user management.
 * Assumes MongoDB is already connected globally at app startup.
 */
const User = require('../models/users');
const Blacklist = require('../models/blacklist');
const jwt = require('jsonwebtoken');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const { ensureStripeCustomer } = require('../services/stripeService');

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

  try {
    // 1. Metering update
    if (event.type === 'billing.meter.summary_updated') {
      const summary = event.data.object;
      const updatedUser = await User.findOneAndUpdate(
        { stripeCustomerId: summary.customer },
        {
          currentUsage: summary.aggregate_value,
          usageLastUpdated: new Date(),
        },
        { returnDocument: 'after' }
      );
      if (updatedUser) {
        console.log(`✅ MongoDB Synced Usage: ${updatedUser.email}`);
      }
    }
    // 2. Credit pack purchases
    else if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      const creditsToAdd = Number(session.metadata?.credits) || 1000;

      const updatedUser = await User.findOneAndUpdate(
        { stripeCustomerId: session.customer },
        { $inc: { credits: creditsToAdd } },
        { returnDocument: 'after' }
      );

      if (updatedUser) {
        console.log(
          `💰 Credits (+${creditsToAdd}) added to ${updatedUser.email}. New balance: ${updatedUser.credits}`
        );
      }
    }
  } catch (err) {
    console.error('❌ Webhook processing error:', err.message);
  }

  res.json({ received: true });
};

// --- AUTH LOGIC ---
exports.register = async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!email || !password) {
      return res
        .status(400)
        .json({ success: false, error: 'Email and password are required' });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const existingUser = await User.findOne({ email: normalizedEmail });
    if (existingUser) {
      return res
        .status(400)
        .json({ success: false, error: 'Email already exists' });
    }

    const user = await User.create({
      name,
      email: normalizedEmail,
      passwordHash: password,
      credits: 1000,
    });
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
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res
        .status(400)
        .json({ success: false, error: 'Email and password are required' });
    }

    const user = await User.findOne({
      email: email.toLowerCase().trim(),
    }).select('+passwordHash');

    if (!user || !(await user.comparePassword(password))) {
      return res
        .status(401)
        .json({ success: false, error: 'Invalid credentials' });
    }

    await ensureStripeCustomer(user);
    console.log(`🔑 User logged in: ${user.email}`);

    const token = signToken(user._id);
    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        stripeCustomerId: user.stripeCustomerId,
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

// --- MIDDLEWARE ---
exports.trackUsage = async (req, res, next) => {
  console.log('DEBUG: trackUsage middleware running for route', req.originalUrl);
  try {
    // Free paths
    const freeRoutes = ['/api/v1/auth/me', '/api/v1/auth/usage'];
    if (freeRoutes.includes(req.originalUrl)) return next();

    if (!req.user) return next();

    const user = await User.findById(req.user.id || req.user._id);
    if (!user) return next();

    // Trial logic
    if (user.isTrial) {
      if (user.trialRequestsUsed < user.trialLimit) {
        await User.findByIdAndUpdate(user._id, {
          $inc: { trialRequestsUsed: 1 },
        });
        console.log(
          `✅ Trial usage for ${user.email}: ${user.trialRequestsUsed + 1}/${user.trialLimit}`
        );
        return next();
      }
      // Trial finished → switch to paid path
      await User.findByIdAndUpdate(user._id, { isTrial: false });
    }

    // Paid guardrail
    if ((user.credits || 0) <= 0) {
      console.log(`🚫 Blocked: ${user.email} has no credits.`);
      return res.status(402).json({
        success: false,
        error: 'Insufficient credits. Please top up.',
      });
    }

    // Stripe meter event (fire-and-forget)
    if (user.stripeCustomerId) {
      stripe.billing.meterEvents
        .create({
          event_name: 'api_request',
          payload: {
            stripe_customer_id: user.stripeCustomerId,
            value: '1',
          },
        })
        .catch((e) => console.error('❌ Stripe Ingestion Error:', e.message));
    }

    await User.findByIdAndUpdate(user._id, {
      $inc: { credits: -1, currentUsage: 1 },
    });

    next();
  } catch (err) {
    console.error('❌ TrackUsage Error:', err.message);
    next();
  }
};

// --- REMAINING METHODS ---
exports.getMe = async (req, res) => {
  try {
    const user = await User.findById(req.user.id || req.user._id)
      .select('-passwordHash')
      .lean();

    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    const userData = {
      ...user,
      isTrial: user.isTrial ?? true,
      trialRemaining: Math.max(
        0,
        (user.trialLimit || 1000) - (user.trialRequestsUsed || 0)
      ),
    };

    res.json({ success: true, user: userData });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

exports.getUsage = async (req, res) => {
  const userId = req.user?.id || req.user?._id;

  if (!userId) {
    console.error('❌ GetUsage Error: No User ID found in request object.');
    return res
      .status(401)
      .json({ success: false, error: 'Unauthorized: User ID missing' });
  }

  console.log(`📥 Fetching dashboard data for User ID: ${userId}`);

  try {
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    const isTrial = user.isTrial ?? true;
    const trialLimit = user.trialLimit || 1000;
    const trialRequestsUsed = user.trialRequestsUsed || 0;
    const trialRemaining = Math.max(0, trialLimit - trialRequestsUsed);

    if (!user.stripeCustomerId) {
      console.log('ℹ️ GetUsage: No Stripe ID found, returning zeros.');
      return res.json({
        success: true,
        data: {
          amount_due: 0,
          quantity: 0,
          currency: 'EUR',
          period_end: '--',
          credits: user.credits || 0,
          isTrial,
          trialRemaining,
          trialLimit,
        },
      });
    }

    console.log(`🔎 Querying Stripe for customer: ${user.stripeCustomerId}`);
    let amountDue = 0;
    let currency = 'EUR';
    let periodEnd = '--';

    try {
      const inv = await stripe.invoices.retrieveUpcoming({
        customer: user.stripeCustomerId,
      });
      amountDue = (inv.amount_remaining || 0) / 100;
      currency = (inv.currency || 'EUR').toUpperCase();
      periodEnd = new Date(inv.next_payment_attempt * 1000).toLocaleDateString();
      console.log(`💰 Stripe Invoice Found: ${amountDue} ${currency}`);
    } catch (e) {
      console.log(
        'ℹ️ GetUsage: No upcoming invoice found (Normal for new users).'
      );
    }

    res.json({
      success: true,
      data: {
        amount_due: amountDue,
        currency,
        quantity: user.currentUsage || 0,
        credits: user.credits || 0,
        isTrial,
        trialRemaining,
        trialLimit,
        period_end: periodEnd,
      },
    });
  } catch (err) {
    console.error('❌ GetUsage Database Error:', err.message);
    res.status(500).json({ success: false, error: 'Internal Server Error' });
  }
};

exports.resetUsage = async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.user.id || req.user._id,
      { currentUsage: 0 },
      { returnDocument: 'after' }
    );
    console.log(`🔄 Usage reset for ${user?.email} → 0`);
    res.json({ success: true, currentUsage: 0 });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

exports.logout = async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (token) await Blacklist.create({ token });
    res.status(200).json({ success: true, message: 'Logged out' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

exports.getAllUsers = async (req, res) => {
  try {
    const users = await User.find().select('-passwordHash');
    res.status(200).json({ success: true, data: users });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

exports.getUserById = async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-passwordHash');
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    res.status(200).json({ success: true, user });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

exports.updateMe = async (req, res) => {
  try {
    // Prevent privilege escalation
    const { role, credits, status, ...safeBody } = req.body;
    const user = await User.findByIdAndUpdate(
      req.user.id || req.user._id,
      safeBody,
      { returnDocument: 'after', runValidators: true }
    ).select('-passwordHash');

    res.status(200).json({ success: true, user });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

exports.updateUser = async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(req.params.id, req.body, {
      returnDocument: 'after',
      runValidators: true,
    }).select('-passwordHash');

    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    res.status(200).json({ success: true, user });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

exports.deleteMe = async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.user.id || req.user._id, {
      status: 'inactive',
      deletedAt: new Date(),
    });
    res.status(204).json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

// JIT provisioning helper (Auth0 → MongoDB)
exports.syncAuth0User = async (req, res) => {
  try {
    const { email, name } = req.user;
    if (!email) {
      return res
        .status(400)
        .json({ success: false, error: 'Email required for sync' });
    }

    const normalizedEmail = email.toLowerCase().trim();
    let user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      console.log(
        `👤 JIT Provisioning: New user detected, creating record for ${normalizedEmail}`
      );
      user = await User.create({
        name: name || 'New User',
        email: normalizedEmail,
        passwordHash: 'AUTH0_MANAGED_ACCOUNT',
      });
      await ensureStripeCustomer(user);
    }

    res.json({ success: true, user });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};
