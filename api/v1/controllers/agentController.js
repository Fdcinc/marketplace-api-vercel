/**
 * @file controllers/agentController.js
 * @description AI Billing Assistant controller using local Ollama (llama3) 
 * with integrated Stripe Billing Portal session generation.
 */
const User = require('../models/users');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

exports.billingAssistant = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ success: false, error: "User not found" });
    }

    const { message } = req.body;
    if (!message || typeof message !== 'string' || message.trim() === '') {
      return res.status(400).json({ success: false, error: "A valid message string is required" });
    }

    // Safely calculate trial fields with fallbacks
    const isTrial = user.isTrial ?? true;
    const trialLimit = user.trialLimit ?? 1000;
    const trialRequestsUsed = user.trialRequestsUsed ?? 0;
    const requestsRemaining = Math.max(0, trialLimit - trialRequestsUsed);

    // 1. Dynamically generate a Stripe Billing Portal session if the user has a customer ID
    let billingPortalUrl = null;
    if (user.stripeCustomerId) {
      try {
        const portalSession = await stripe.billingPortal.sessions.create({
          customer: user.stripeCustomerId,
          return_url: process.env.STRIPE_RETURN_URL || 'http://localhost:5173/dashboard'
        });
        billingPortalUrl = portalSession.url;
      } catch (stripeErr) {
        console.warn("⚠️ Could not generate Stripe billing portal session:", stripeErr.message);
      }
    }

    // 2. Structured Prompt Template including the portal link context
    const structuredPrompt = `
You are Jarvis, an expert AI billing and developer platform assistant for our API Marketplace. 
Your goal is to assist users politely, accurately, and concisely regarding their account status, remaining credits, trial limits, and API integration questions.

Current User Context:
- Name: ${user.name || 'Developer'}
- Email: ${user.email || 'Not provided'}
- Plan Type: ${isTrial ? 'Trial Tier' : 'Active Paid Tier'}
- Trial Usage: ${trialRequestsUsed} / ${trialLimit} requests used
- Requests Remaining: ${requestsRemaining}
- Stripe Billing Portal URL: ${billingPortalUrl || 'Not available (User must link a card or subscribe first)'}

Rules:
1. Always base your billing answers on the provided user context.
2. If the user asks to manage subscriptions, update payment methods, or buy credits, provide them with their direct Stripe Billing Portal URL if available.
3. Keep technical explanations short and answers concise.

User Question: ${message.trim()}
`;

    const ollamaHost = process.env.OLLAMA_HOST || 'http://localhost:11434';
    const ollamaModel = process.env.OLLAMA_MODEL || 'llama3';

    // 3. Forward the structured prompt to your local Ollama instance
    const response = await fetch(`${ollamaHost}/api/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: ollamaModel,
        prompt: structuredPrompt,
        stream: false
      })
    });

    if (!response.ok) {
      throw new Error(`Ollama server returned status ${response.status}`);
    }

    const data = await response.json();
    
    res.json({ 
      success: true, 
      response: data.response || "I'm sorry, I couldn't generate a response.",
      portalUrl: billingPortalUrl // Also pass it cleanly in JSON for frontend buttons if needed
    });

  } catch (err) {
    console.error("❌ Agent Controller Error:", err.message);
    res.status(500).json({ success: false, error: "Failed to process AI assistant request" });
  }
};