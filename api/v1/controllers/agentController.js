/**
 * @file controllers/agentController.js
 * @description Tool-using Billing Assistant (Jarvis)
 * Uses local Ollama + real MCP tools
 */
const User = require('../models/users');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const { getOpenApiSpec } = require('../config/openapi');

const OLLAMA_HOST = process.env.OLLAMA_HOST || 'http://localhost:11434';
const OLLAMA_MODEL = process.env.OLLAMA_MODEL || 'llama3';

// ────────────────────────────────────────────────
// Helper: call Ollama
// ────────────────────────────────────────────────
async function askOllama(prompt) {
  const response = await fetch(`${OLLAMA_HOST}/api/generate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: OLLAMA_MODEL,
      prompt,
      stream: false,
      options: { temperature: 0.2 },
    }),
  });

  if (!response.ok) {
    throw new Error(`Ollama error: ${response.status}`);
  }

  const data = await response.json();
  return data.response?.trim() || '';
}

// ────────────────────────────────────────────────
// Real tool implementations
// ────────────────────────────────────────────────
async function executeTool(name, args = {}, userId) {
  if (name === 'get_billing_status') {
    const user = await User.findById(userId).select('-passwordHash');
    if (!user) return { error: 'User not found' };

    const trialRemaining = Math.max(
      0,
      (user.trialLimit || 1000) - (user.trialRequestsUsed || 0)
    );

    return {
      name: user.name,
      email: user.email,
      isTrial: user.isTrial ?? true,
      trialRemaining,
      credits: user.credits || 0,
      currentUsage: user.currentUsage || 0,
    };
  }

  if (name === 'create_billing_portal') {
    const user = await User.findById(userId);
    if (!user?.stripeCustomerId) {
      return { error: 'No Stripe customer linked yet' };
    }

    const session = await stripe.billingPortal.sessions.create({
      customer: user.stripeCustomerId,
      return_url: `${process.env.CLIENT_URL || 'http://localhost:5173'}/billing`,
    });

    return { portalUrl: session.url };
  }

  if (name === 'create_credit_checkout') {
    const user = await User.findById(userId);
    if (!user?.stripeCustomerId) {
      return { error: 'No Stripe customer linked yet' };
    }

    const credits = args.credits || 1000;
    const amountCents = args.amountCents || 1000;

    const session = await stripe.checkout.sessions.create({
      customer: user.stripeCustomerId,
      mode: 'payment',
      line_items: [
        {
          price_data: {
            currency: 'usd',
            product_data: { name: `API Credit Pack (${credits} requests)` },
            unit_amount: amountCents,
          },
          quantity: 1,
        },
      ],
      metadata: { userId: userId.toString(), credits: String(credits) },
      success_url: `${process.env.CLIENT_URL || 'http://localhost:5173'}/billing?billing_success=true`,
      cancel_url: `${process.env.CLIENT_URL || 'http://localhost:5173'}/billing?billing_canceled=true`,
    });

    return { checkoutUrl: session.url, credits, amountCents };
  }

  if (name === 'switch_to_credits') {
    const user = await User.findById(userId);
    if (!user) return { error: 'User not found' };

    if (!user.isTrial) {
      return { message: `Already on credits. Balance: ${user.credits || 0}` };
    }

    const remaining = Math.max(
      0,
      (user.trialLimit || 1000) - (user.trialRequestsUsed || 0)
    );

    const updated = await User.findByIdAndUpdate(
      userId,
      {
        isTrial: false,
        $inc: { credits: remaining },
        trialRequestsUsed: user.trialLimit || 1000,
      },
      { returnDocument: 'after' }
    );

    return {
      message: `Trial ended. Added ${remaining} credits.`,
      newBalance: updated.credits,
    };
  }

  if (name === 'get_openapi') {
    return getOpenApiSpec();
  }

  return { error: `Unknown tool: ${name}` };
}

// ────────────────────────────────────────────────
// Main controller
// ────────────────────────────────────────────────
exports.billingAssistant = async (req, res) => {
  try {
    const userId = req.user.id || req.user._id;
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    const { message } = req.body;
    if (!message || typeof message !== 'string' || !message.trim()) {
      return res.status(400).json({ success: false, error: 'Message is required' });
    }

    // Step 1: Decide which tool to use
    const toolDecisionPrompt = `
You are a tool-routing assistant. 
Available tools:
- get_billing_status → get current credits, trial status, usage
- create_billing_portal → generate a link to manage payment methods / invoices
- create_credit_checkout → arguments: { "credits": number, "amountCents": number } buy credits via Stripe Checkout
- switch_to_credits → end trial early and convert remaining trial to credits
- get_openapi → get the API documentation
- none → if no tool is needed

User question: "${message.trim()}"

Reply with ONLY a JSON object, nothing else:
{"tool": "tool_name_or_none", "arguments": {}}
`;

    const decisionRaw = await askOllama(toolDecisionPrompt);

    let decision = { tool: 'none', arguments: {} };
    try {
      const jsonMatch = decisionRaw.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        decision = JSON.parse(jsonMatch[0]);
      }
    } catch (e) {
      console.warn('Failed to parse tool decision, falling back to none');
    }

    console.log('🛠️ Tool decision:', decision);

    // Step 2: Execute the tool (if any)
    let toolResult = null;
    if (decision.tool && decision.tool !== 'none') {
      toolResult = await executeTool(decision.tool, decision.arguments || {}, userId);
      console.log('🔧 Tool result:', toolResult);
    }

    // Step 3: Final natural language answer
    const finalPrompt = `
You are Jarvis, a helpful billing assistant for an API Marketplace.

User question: ${message.trim()}

${toolResult ? `Tool result:\n${JSON.stringify(toolResult, null, 2)}` : 'No tool was needed.'}

Rules:
- Be friendly and concise
- If a portalUrl or checkoutUrl is present, always include the full link
- Use the exact numbers from the tool result
- Never invent data

Give a clear final answer:
`;

    const finalAnswer = await askOllama(finalPrompt);

    res.json({
      success: true,
      response: finalAnswer,
      toolUsed: decision.tool !== 'none' ? decision.tool : null,
      toolResult: toolResult || null,
    });
  } catch (err) {
    console.error('❌ Agent Controller Error:', err.message);
    res.status(500).json({
      success: false,
      error: 'Failed to process AI assistant request',
    });
  }
};