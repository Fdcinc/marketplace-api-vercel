/**
 * @file middleware/agentMetering.js
 * @description Agent-specific metering: tracks usage but doesn't block on credits.
 * Agents pay via MPP (402 flow), so they don't need pre-purchased credits.
 */
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

async function agentMetering(req, res, next) {
  try {
    // Check if this is an agent request (paid via MPP)
    const isAgentRequest = req.headers['x-agent-id'] || 
                          req.headers['authorization']?.startsWith('Payment') ||
                          req.payment; // Set by mppx middleware
    
    if (isAgentRequest) {
      // Agent flow: track usage but don't block on credits
      console.log('🤖 Agent request detected, tracking usage without credit check');
      
      // Fire-and-forget: report to Stripe meter for analytics
      if (req.user?.stripeCustomerId) {
        stripe.billing.meterEvents
          .create({
            event_name: 'api_request',
            payload: {
              stripe_customer_id: req.user.stripeCustomerId,
              value: '1',
            },
          })
          .catch((e) => console.error('❌ Stripe Ingestion Error:', e.message));
      }
      
      return next(); // ✅ Agents pass through freely
    }
    
    // Human/developer flow: use existing trackUsage middleware
    next();
  } catch (err) {
    console.error('❌ AgentMetering Error:', err.message);
    next(); // Fail open to keep API available
  }
}

module.exports = agentMetering;