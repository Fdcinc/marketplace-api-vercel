/**
 * @file controllers/agentController.js
 * @description AI Billing Assistant controller using local Ollama (llama3).
 * Forwards user query + structured billing context to local LLM model.
 */
const User = require('../models/users');

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

    // 1. Structured Prompt Template
    const structuredPrompt = `
You are Jarvis, an expert AI billing and developer platform assistant for our API Marketplace. 
Your goal is to assist users politely, accurately, and concisely regarding their account status, remaining credits, trial limits, and API integration questions.

Current User Context:
- Name: ${user.name || 'Developer'}
- Email: ${user.email || 'N/A'}
- Plan Type: ${isTrial ? 'Trial Tier' : 'Active Paid Tier'}
- Trial Usage: ${trialRequestsUsed} / ${trialLimit} requests used
- Requests Remaining: ${requestsRemaining}

Rules:
1. Always base your billing answers on the provided user context.
2. If the user asks about upgrading or getting more requests, gently point them to the billing portal or credit purchase options.
3. Keep technical explanations short and answers concise.

User Question: ${message.trim()}
`;

    const ollamaHost = process.env.OLLAMA_HOST || 'http://localhost:11434';
    const ollamaModel = process.env.OLLAMA_MODEL || 'llama3';

    // 2. Forward the structured prompt to your local Ollama instance
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
      response: data.response || "I'm sorry, I couldn't generate a response."
    });

  } catch (err) {
    console.error("❌ Ollama Connection Error:", err.message);
    res.status(500).json({ success: false, error: "Failed to connect to local AI model" });
  }
};