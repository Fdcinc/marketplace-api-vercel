/**
 * @file v1/routes/mcp.js
 * @description MCP (Model Context Protocol) HTTP endpoint for agents
 */

// routes/mcp.js
const express = require('express');
const router = express.Router();
const { getOpenApiSpec } = require('../config/openapi');
const User = require('../models/users');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const { protect } = require('../middleware/authMiddleware');

// ────────────────────────────────────────────────
// GET /api/v1/mcp/tools  – discovery
// ────────────────────────────────────────────────
router.get('/tools', (req, res) => {
  res.json({
    tools: [
      // Existing paid tools
      {
        name: 'get_mpp_data',
        description: 'Premium marketplace data. Costs $0.50 via MPP.',
        inputSchema: { type: 'object', properties: {}, required: [] },
        payment: { amount: '0.50', currency: 'usd', endpoint: 'POST /api/v1/mpp/mpp-data' },
      },
      {
        name: 'get_premium_data',
        description: 'Premium insights. Costs $0.25 via MPP.',
        inputSchema: { type: 'object', properties: {}, required: [] },
        payment: { amount: '0.25', currency: 'usd', endpoint: 'GET /api/v1/mpp/premium' },
      },
      {
        name: 'get_openapi',
        description: 'Full OpenAPI specification of the Marketplace API.',
        inputSchema: { type: 'object', properties: {} },
      },

      // ── New billing tools ──────────────────────
      {
        name: 'get_billing_status',
        description: 'Get the current user trial status, credits remaining, and usage.',
        inputSchema: {
          type: 'object',
          properties: {
            userId: { type: 'string', description: 'MongoDB user _id (optional if authenticated)' },
          },
        },
      },
      {
        name: 'create_billing_portal',
        description: 'Generate a Stripe Customer Portal link so the user can manage cards / invoices.',
        inputSchema: {
          type: 'object',
          properties: {
            userId: { type: 'string' },
          },
        },
      },
      {
        name: 'create_credit_checkout',
        description: 'Create a one-time Stripe Checkout session to buy a credit pack.',
        inputSchema: {
          type: 'object',
          properties: {
            userId: { type: 'string' },
            credits: { type: 'integer', default: 1000 },
            amountCents: { type: 'integer', default: 1000, description: 'Price in cents' },
          },
        },
      },
      {
        name: 'switch_to_credits',
        description: 'End the free trial early and convert remaining trial requests into credits.',
        inputSchema: {
          type: 'object',
          properties: {
            userId: { type: 'string' },
          },
        },
      },
    ],
  });
});

// ────────────────────────────────────────────────
// POST /api/v1/mcp/call  – execute a tool
// ────────────────────────────────────────────────
router.post('/call', protect, async (req, res) => {
  const { name, arguments: args = {} } = req.body;
  const userId = args.userId || req.user._id.toString();

  try {
    // ── get_billing_status ───────────────────────
    if (name === 'get_billing_status') {
      const user = await User.findById(userId).select('-passwordHash');
      if (!user) return res.status(404).json({ isError: true, content: [{ type: 'text', text: 'User not found' }] });

      const remaining = Math.max(0, (user.trialLimit || 1000) - (user.trialRequestsUsed || 0));
      return res.json({
        content: [{
          type: 'text',
          text: JSON.stringify({
            name: user.name,
            email: user.email,
            isTrial: user.isTrial ?? true,
            trialRemaining: remaining,
            credits: user.credits || 0,
            currentUsage: user.currentUsage || 0,
          }, null, 2),
        }],
      });
    }

    // ── create_billing_portal ────────────────────
    if (name === 'create_billing_portal') {
      const user = await User.findById(userId);
      if (!user?.stripeCustomerId) {
        return res.json({
          content: [{ type: 'text', text: 'No Stripe customer linked. User must complete a purchase first.' }],
        });
      }
      const session = await stripe.billingPortal.sessions.create({
        customer: user.stripeCustomerId,
        return_url: process.env.CLIENT_URL + '/billing',
      });
      return res.json({
        content: [{ type: 'text', text: `Billing Portal: ${session.url}` }],
      });
    }

    // ── create_credit_checkout ───────────────────
    if (name === 'create_credit_checkout') {
      const user = await User.findById(userId);
      if (!user?.stripeCustomerId) {
        return res.json({ content: [{ type: 'text', text: 'No Stripe customer linked.' }] });
      }
      const credits = args.credits || 1000;
      const amountCents = args.amountCents || 1000;

      const session = await stripe.checkout.sessions.create({
        customer: user.stripeCustomerId,
        mode: 'payment',
        line_items: [{
          price_data: {
            currency: 'usd',
            product_data: { name: `API Credit Pack (${credits} requests)` },
            unit_amount: amountCents,
          },
          quantity: 1,
        }],
        metadata: { userId, credits: String(credits) },
        success_url: `${process.env.CLIENT_URL}/billing?billing_success=true`,
        cancel_url: `${process.env.CLIENT_URL}/billing?billing_canceled=true`,
      });

      return res.json({
        content: [{ type: 'text', text: `Checkout URL: ${session.url}` }],
      });
    }

    // ── switch_to_credits ────────────────────────
    if (name === 'switch_to_credits') {
      // Re-use the exact logic from billingController.switchToCredits
      const user = await User.findById(userId);
      if (!user) return res.status(404).json({ isError: true, content: [{ type: 'text', text: 'User not found' }] });

      if (!user.isTrial) {
        return res.json({
          content: [{ type: 'text', text: `Already on credits. Balance: ${user.credits || 0}` }],
        });
      }

      const remaining = Math.max(0, (user.trialLimit || 1000) - (user.trialRequestsUsed || 0));
      const updated = await User.findByIdAndUpdate(
        userId,
        { isTrial: false, $inc: { credits: remaining }, trialRequestsUsed: user.trialLimit || 1000 },
        { returnDocument: 'after' }
      );

      return res.json({
        content: [{
          type: 'text',
          text: `Trial ended. Added ${remaining} credits. New balance: ${updated.credits}`,
        }],
      });
    }

    // ── Existing paid tools (delegate) ───────────
    if (name === 'get_openapi') {
      return res.json({
        content: [{ type: 'text', text: JSON.stringify(getOpenApiSpec(), null, 2) }],
      });
    }

    // Fallback for the paid ones – tell the agent to use the MPP endpoints
    if (['get_mpp_data', 'get_premium_data'].includes(name)) {
      return res.json({
        content: [{
          type: 'text',
          text: `This tool requires payment. Call the corresponding MPP endpoint and handle the 402.`,
        }],
        paymentRequired: true,
      });
    }

    res.status(404).json({
      content: [{ type: 'text', text: `Unknown tool: ${name}` }],
      isError: true,
    });
  } catch (err) {
    console.error('MCP call error:', err);
    res.status(500).json({
      content: [{ type: 'text', text: err.message }],
      isError: true,
    });
  }
});

module.exports = router;