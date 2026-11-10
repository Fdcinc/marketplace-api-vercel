const rateLimit = require('express-rate-limit');

const standardLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, 
  max: 100, 
  standardHeaders: true, 
  legacyHeaders: false, 
  message: { success: false, error: 'Too many requests. Please slow down.' },
});

const strictLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, 
  max: 5, 
  message: { success: false, error: 'Rate limit exceeded for premium compute endpoint.' },
});

module.exports = { standardLimiter, strictLimiter };