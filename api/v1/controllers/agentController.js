// controllers/agentController.js
const User = require('../models/users');


exports.billingAssistant = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    const { message } = req.body;

  // controllers/agentController.js
  const billingContext = `
  User: ${user.name},
  Plan: ${user.isTrial ? 'Trial' : 'Active'},
  Trial Usage: ${user.trialRequestsUsed} / ${user.trialLimit},
  Requests Remaining: ${user.trialLimit - user.trialRequestsUsed}
`;

    // Forward the request to your local Ollama instance
    const response = await fetch('http://localhost:11434/api/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'llama3',
        prompt: `You are a helpful billing assistant. Context: ${billingContext}. User asks: ${message}`,
        stream: false
      })
    });

    const data = await response.json();
    
    res.json({ 
      success: true, 
      response: data.response 
    });
  } catch (err) {
    console.error("❌ Ollama Connection Error:", err.message);
    res.status(500).json({ success: false, error: "Failed to connect to local AI model" });
  }
};